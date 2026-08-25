/* Bounded hostname resolution.
 *
 * getaddrinfo takes no deadline and cannot be cancelled, on either
 * platform, so the only way to put a bound on it is to run it
 * somewhere the caller can stop waiting for. This resolves on a
 * detached worker and has the caller wait on a condition variable
 * until either the worker finishes or the deadline passes.
 *
 * Nothing here can make a stuck getaddrinfo stop. The worker that
 * outlives its caller keeps running until the platform resolver gives
 * up on its own -- bounded in practice (glibc: RES_TIMEOUT x attempts
 * x nameservers; Windows: the DNS client's own cap), which is why an
 * abandoned worker is a bounded-lifetime thread rather than a leak.
 * What this buys is that the CALLER is bounded, which is the part an
 * application can otherwise do nothing about.
 *
 * That split ownership is the whole of the difficulty. Caller and
 * worker each hold a reference to the job; the one that puts the last
 * reference down frees it. The results are written into the job and
 * copied out by the caller while it still holds the lock, so a worker
 * finishing late writes only into storage it still owns and never into
 * the caller's buffer, which by then may be gone.
 *
 * A test seam sits at the bottom of the file. It is deliberately not
 * bound by AHT.DNS: reaching it means importing a symbol with
 * _for_test in its name on purpose. It is compiled unconditionally
 * because the alternative -- a -D that only the test build sets --
 * would have to join Aht.Variant to keep object directories from
 * being shared between builds that disagree about it, and that is a
 * build dimension for a hook.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <netdb.h>
#  include <sys/socket.h>
#  include <arpa/inet.h>
#  include <pthread.h>
#  include <time.h>
#endif

#define AHT_DNS_MAX_ADDRS 16
#define AHT_DNS_ADDRSTRLEN 46   /* INET6_ADDRSTRLEN */

/* Status codes, mirrored by AHT.DNS.Resolve_Status. */
#define AHT_DNS_OK       0
#define AHT_DNS_TIMEOUT  1
#define AHT_DNS_FAILED   2
#define AHT_DNS_INTERNAL 3

/* ---- the two thread APIs, behind one set of names ---------------- */

#ifdef _WIN32
typedef CRITICAL_SECTION    aht_mutex;
typedef CONDITION_VARIABLE  aht_cond;
#  define AHT_MUTEX_INIT(m)    InitializeCriticalSection(m)
#  define AHT_MUTEX_FINI(m)    DeleteCriticalSection(m)
#  define AHT_LOCK(m)          EnterCriticalSection(m)
#  define AHT_UNLOCK(m)        LeaveCriticalSection(m)
#  define AHT_COND_INIT(c)     InitializeConditionVariable(c)
#  define AHT_COND_FINI(c)     ((void) 0)
#  define AHT_COND_SIGNAL(c)   WakeConditionVariable(c)
#else
typedef pthread_mutex_t     aht_mutex;
typedef pthread_cond_t      aht_cond;
#  define AHT_MUTEX_INIT(m)    pthread_mutex_init((m), NULL)
#  define AHT_MUTEX_FINI(m)    pthread_mutex_destroy(m)
#  define AHT_LOCK(m)          pthread_mutex_lock(m)
#  define AHT_UNLOCK(m)        pthread_mutex_unlock(m)
#  define AHT_COND_FINI(c)     pthread_cond_destroy(c)
#  define AHT_COND_SIGNAL(c)   pthread_cond_signal(c)
#endif

/* Milliseconds on a monotonic clock. A wall clock would let a step
 * (NTP, a manual change) shorten or extend a deadline that was
 * supposed to measure elapsed time. */
static unsigned long long
aht_now_ms(void)
{
#ifdef _WIN32
    return (unsigned long long) GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long) ts.tv_sec * 1000ULL
         + (unsigned long long) (ts.tv_nsec / 1000000L);
#endif
}

/* ---- the job ----------------------------------------------------- */

typedef struct {
    char  addrs[AHT_DNS_MAX_ADDRS][AHT_DNS_ADDRSTRLEN];
    int   count;
    int   status;
    int   done;

    /* refs is 2 from the moment the worker is spawned: one for the
     * caller, one for the worker. Both are given back exactly once. */
    int   refs;

    aht_mutex m;
    aht_cond  cv;

    char  host[256];
    char  svc[32];
} aht_dns_job;

/* The seam. Fills job->addrs / count and returns AHT_DNS_OK or
 * AHT_DNS_FAILED. Everything above this line is the production path
 * whichever function is installed, which is the point: a test that
 * replaced more than the lookup itself would not be testing the
 * waiting, the deadline or the handoff. */
typedef int (*aht_dns_fn)(aht_dns_job *job);

static int aht_dns_real(aht_dns_job *job);
static aht_dns_fn aht_resolver = aht_dns_real;

static int
aht_dns_real(aht_dns_job *job)
{
    struct addrinfo  hints;
    struct addrinfo *res = NULL, *p = NULL;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(job->host, job->svc, &hints, &res);
    if (rc != 0 || res == NULL)
        return AHT_DNS_FAILED;

    job->count = 0;
    for (p = res; p != NULL && job->count < AHT_DNS_MAX_ADDRS;
         p = p->ai_next) {
        void *sin;
        if (p->ai_family == AF_INET)
            sin = &((struct sockaddr_in *) p->ai_addr)->sin_addr;
        else if (p->ai_family == AF_INET6)
            sin = &((struct sockaddr_in6 *) p->ai_addr)->sin6_addr;
        else
            continue;

        if (inet_ntop(p->ai_family, sin, job->addrs[job->count],
                      AHT_DNS_ADDRSTRLEN) != NULL)
            job->count++;
    }

    freeaddrinfo(res);
    return job->count > 0 ? AHT_DNS_OK : AHT_DNS_FAILED;
}

/* Give back one reference; the last one out frees. The count is read
 * under the lock and the free happens after it is dropped, so the
 * mutex is never destroyed by a thread still inside it. */
static void
aht_job_release(aht_dns_job *job)
{
    int remaining;

    AHT_LOCK(&job->m);
    remaining = --job->refs;
    AHT_UNLOCK(&job->m);

    if (remaining == 0) {
        AHT_COND_FINI(&job->cv);
        AHT_MUTEX_FINI(&job->m);
        free(job);
    }
}

#ifdef _WIN32
static DWORD WINAPI
aht_dns_worker(LPVOID arg)
#else
static void *
aht_dns_worker(void *arg)
#endif
{
    aht_dns_job *job = (aht_dns_job *) arg;
    int status = aht_resolver(job);

    AHT_LOCK(&job->m);
    job->status = status;
    job->done   = 1;
    AHT_COND_SIGNAL(&job->cv);
    AHT_UNLOCK(&job->m);

    aht_job_release(job);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

#ifdef _WIN32
/* getaddrinfo needs Winsock started. GNAT.Sockets does this too, but
 * a resolve can be the first thing a program does, and WSAStartup is
 * reference-counted so calling it again is harmless. */
static INIT_ONCE aht_wsa_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK
aht_wsa_start(PINIT_ONCE o, PVOID p, PVOID *c)
{
    WSADATA d;
    (void) o; (void) p; (void) c;
    WSAStartup(MAKEWORD(2, 2), &d);
    return TRUE;
}
#endif

/* Resolve host:svc, waiting at most timeout_ms. Writes up to
 * max_addrs presentation-form literals into out (each
 * AHT_DNS_ADDRSTRLEN bytes, NUL-terminated) and the number written
 * into *count. timeout_ms < 0 waits indefinitely. */
int
aht_dns_resolve(const char *host, const char *svc, long timeout_ms,
                char *out, int max_addrs, int *count)
{
    aht_dns_job *job;
    int status, n, i;
    unsigned long long deadline;

    if (host == NULL || out == NULL || count == NULL || max_addrs <= 0)
        return AHT_DNS_INTERNAL;

    *count = 0;

#ifdef _WIN32
    InitOnceExecuteOnce(&aht_wsa_once, aht_wsa_start, NULL, NULL);
#endif

    job = (aht_dns_job *) calloc(1, sizeof *job);
    if (job == NULL)
        return AHT_DNS_INTERNAL;

    strncpy(job->host, host, sizeof job->host - 1);
    strncpy(job->svc, svc != NULL ? svc : "", sizeof job->svc - 1);
    job->status = AHT_DNS_FAILED;

    AHT_MUTEX_INIT(&job->m);
#ifdef _WIN32
    AHT_COND_INIT(&job->cv);
#else
    {
        /* Monotonic, to match aht_now_ms and pthread_cond_timedwait's
         * absolute deadline below. */
        pthread_condattr_t a;
        pthread_condattr_init(&a);
        pthread_condattr_setclock(&a, CLOCK_MONOTONIC);
        pthread_cond_init(&job->cv, &a);
        pthread_condattr_destroy(&a);
    }
#endif

    /* Both references exist before the worker does, so the worker can
     * never observe a count that has not yet counted it. */
    job->refs = 2;

#ifdef _WIN32
    {
        HANDLE t = CreateThread(NULL, 0, aht_dns_worker, job, 0, NULL);
        if (t == NULL) {
            job->refs = 1;             /* no worker to give one back */
            aht_job_release(job);
            return AHT_DNS_INTERNAL;
        }
        CloseHandle(t);                /* detached */
    }
#else
    {
        pthread_t t;
        pthread_attr_t a;
        int rc;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        rc = pthread_create(&t, &a, aht_dns_worker, job);
        pthread_attr_destroy(&a);
        if (rc != 0) {
            job->refs = 1;
            aht_job_release(job);
            return AHT_DNS_INTERNAL;
        }
    }
#endif

    deadline = aht_now_ms()
             + (timeout_ms < 0 ? 0 : (unsigned long long) timeout_ms);

    AHT_LOCK(&job->m);
    while (!job->done) {
        if (timeout_ms < 0) {
#ifdef _WIN32
            SleepConditionVariableCS(&job->cv, &job->m, INFINITE);
#else
            pthread_cond_wait(&job->cv, &job->m);
#endif
        } else {
            unsigned long long now = aht_now_ms();
            if (now >= deadline)
                break;
#ifdef _WIN32
            SleepConditionVariableCS(&job->cv, &job->m,
                                     (DWORD) (deadline - now));
#else
            {
                struct timespec ts;
                ts.tv_sec  = (time_t) (deadline / 1000ULL);
                ts.tv_nsec = (long) ((deadline % 1000ULL) * 1000000ULL);
                pthread_cond_timedwait(&job->cv, &job->m, &ts);
            }
#endif
        }
    }

    if (job->done) {
        status = job->status;
        n = job->count > max_addrs ? max_addrs : job->count;
        for (i = 0; i < n; i++)
            memcpy(out + (size_t) i * AHT_DNS_ADDRSTRLEN,
                   job->addrs[i], AHT_DNS_ADDRSTRLEN);
        *count = (status == AHT_DNS_OK) ? n : 0;
    } else {
        status = AHT_DNS_TIMEOUT;
    }
    AHT_UNLOCK(&job->m);

    aht_job_release(job);
    return status;
}

/* ---- test seam --------------------------------------------------- *
 *
 * Not bound by AHT.DNS. See the note at the top of the file.
 *
 * The fake sleeps and then answers with canned literals. Sleeping is
 * what makes the timeout path deterministic: no nameserver, no
 * resolv.conf, no network, and identical behaviour under wine.
 *
 * aht_dns_fake_completions_for_test is the part that matters most. A
 * caller returning at its deadline is equally consistent with "the
 * worker was abandoned correctly" and "no worker ever ran", so the
 * fake counts its own completions AFTER waking, letting a test wait
 * for the abandoned worker and observe that it finished late rather
 * than assume it. */

static int aht_fake_sleep_ms = 0;
static int aht_fake_addrs    = 1;

static aht_mutex aht_fake_m;
static int       aht_fake_ready = 0;
static int       aht_fake_completions = 0;

static int
aht_dns_fake(aht_dns_job *job)
{
    int i;

#ifdef _WIN32
    Sleep((DWORD) aht_fake_sleep_ms);
#else
    {
        struct timespec ts;
        ts.tv_sec  = aht_fake_sleep_ms / 1000;
        ts.tv_nsec = (long) (aht_fake_sleep_ms % 1000) * 1000000L;
        nanosleep(&ts, NULL);
    }
#endif

    job->count = aht_fake_addrs > AHT_DNS_MAX_ADDRS
               ? AHT_DNS_MAX_ADDRS : aht_fake_addrs;
    for (i = 0; i < job->count; i++) {
        /* 127.0.0.1, 127.0.0.2, ... — distinct so a test can tell
         * ordering and count apart from a single canned answer. */
        snprintf(job->addrs[i], AHT_DNS_ADDRSTRLEN, "127.0.0.%d", i + 1);
    }

    AHT_LOCK(&aht_fake_m);
    aht_fake_completions++;
    AHT_UNLOCK(&aht_fake_m);

    return job->count > 0 ? AHT_DNS_OK : AHT_DNS_FAILED;
}

void
aht_dns_install_fake_for_test(int sleep_ms, int n_addrs)
{
    if (!aht_fake_ready) {
        AHT_MUTEX_INIT(&aht_fake_m);
        aht_fake_ready = 1;
    }
    aht_fake_sleep_ms = sleep_ms;
    aht_fake_addrs    = n_addrs;
    aht_resolver      = aht_dns_fake;
}

void
aht_dns_restore_real_for_test(void)
{
    aht_resolver = aht_dns_real;
}

int
aht_dns_fake_completions_for_test(void)
{
    int n;
    if (!aht_fake_ready)
        return 0;
    AHT_LOCK(&aht_fake_m);
    n = aht_fake_completions;
    AHT_UNLOCK(&aht_fake_m);
    return n;
}
