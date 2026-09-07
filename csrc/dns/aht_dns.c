/*  Copyright (C) 2026 Aldo Nicolas Bruno
 *  SPDX-License-Identifier: Apache-2.0
 */

/* Bounded hostname resolution.
 *
 * getaddrinfo takes no deadline and cannot be cancelled on either
 * platform, so the lookup runs on a detached worker and the caller
 * waits for the worker or the deadline. An abandoned worker runs
 * until the platform resolver gives up (glibc: RES_TIMEOUT x
 * attempts x nameservers; Windows: the DNS client's cap). Caller and
 * worker each hold a reference to the job; the last release frees
 * it, and results are copied out under the job's lock, so a late
 * worker never writes into the caller's buffer.
 * The _for_test seam at the bottom is compiled unconditionally.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <process.h>
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
/*
 * The Windows half is written to the XP API: no condition variable,
 * no GetTickCount64 (both Vista+). The loader resolves imports
 * eagerly, so one Vista-only symbol from KERNEL32 fails the whole
 * image on XP.
 */

#ifdef _WIN32
typedef CRITICAL_SECTION    aht_mutex;
#  define AHT_MUTEX_INIT(m)    InitializeCriticalSection(m)
#  define AHT_MUTEX_FINI(m)    DeleteCriticalSection(m)
#  define AHT_LOCK(m)          EnterCriticalSection(m)
#  define AHT_UNLOCK(m)        LeaveCriticalSection(m)
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

/* A monotonic tick and the elapsed milliseconds since one; a wall
 * clock would let an NTP step move the deadline. Elapsed since a
 * start, not an absolute deadline: GetTickCount is 32 bits and wraps
 * every 49.7 days, and subtraction in the counter's width stays
 * correct across a wrap for any interval shorter than the period. */
#ifdef _WIN32
typedef DWORD aht_tick;

static aht_tick
aht_tick_now(void)
{
    return GetTickCount();
}

static unsigned long
aht_elapsed_ms(aht_tick start)
{
    return (unsigned long) (DWORD) (GetTickCount() - start);
}
#else
typedef struct timespec aht_tick;

static aht_tick
aht_tick_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts;
}

static unsigned long
aht_elapsed_ms(aht_tick start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (unsigned long)
           ((now.tv_sec - start.tv_sec) * 1000L
            + (now.tv_nsec - start.tv_nsec) / 1000000L);
}
#endif

/* ---- presentation form ------------------------------------------- */
/*
 * Hand-rolled: ws2_32 exports inet_ntop only from Vista on. Shared
 * with the POSIX build so both targets emit the same literal and the
 * posix suite exercises it on every run.
 */

static void
aht_fmt_ipv4(const unsigned char *b, char *out, size_t cap)
{
    snprintf(out, cap, "%u.%u.%u.%u",
             (unsigned) b[0], (unsigned) b[1],
             (unsigned) b[2], (unsigned) b[3]);
}

static void
aht_fmt_ipv6(const unsigned char *b, char *out, size_t cap)
{
    unsigned group[8];
    int i;
    int run_start = -1, run_len = 0;
    int best_start = -1, best_len = 0;
    size_t n = 0;

    for (i = 0; i < 8; i++)
        group[i] = ((unsigned) b[2 * i] << 8) | (unsigned) b[2 * i + 1];

    /* Longest run of zero groups, leftmost winning a tie, and only if
     * it covers two or more: RFC 5952 4.2. A single zero group is
     * written as "0", because "::" for one group is shorter to write
     * and ambiguous to read back. */
    for (i = 0; i < 8; i++) {
        if (group[i] == 0) {
            if (run_start < 0) {
                run_start = i;
                run_len = 0;
            }
            run_len++;
            if (run_len > best_len) {
                best_len = run_len;
                best_start = run_start;
            }
        } else {
            run_start = -1;
            run_len = 0;
        }
    }
    if (best_len < 2) {
        best_start = -1;
        best_len = 0;
    }

    /* ::ffff:a.b.c.d for a v4-mapped address. The hex form is a
     * correct reading of the same 16 bytes, but a caller comparing
     * against a v4 literal would not recognise it. */
    if (best_start == 0 && best_len == 5 && group[5] == 0xffffu) {
        char v4[16];
        aht_fmt_ipv4(b + 12, v4, sizeof v4);
        snprintf(out, cap, "::ffff:%s", v4);
        return;
    }

    out[0] = '\0';
    for (i = 0; i < 8; i++) {
        if (i == best_start) {
            n += (size_t) snprintf(out + n, cap - n, "::");
            i += best_len - 1;      /* the loop's own i++ takes the rest */
            continue;
        }
        /* One separator between groups, and never a third colon
         * against the run's own pair. */
        if (i > 0 && out[n - 1] != ':')
            n += (size_t) snprintf(out + n, cap - n, ":");
        n += (size_t) snprintf(out + n, cap - n, "%x", group[i]);
    }
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
#ifdef _WIN32
    /* A manual-reset event, set once when done latches. One waiter,
     * one signaller and a predicate that never goes back is the whole
     * of what a condition variable would be used for here, and an
     * event is the part of that XP has. Manual-reset so a wait that
     * starts after the worker finished returns at once. */
    HANDLE    done_ev;
#else
    aht_cond  cv;
#endif

    char  host[256];
    char  svc[32];
} aht_dns_job;

/* The seam. Fills job->addrs / count and returns AHT_DNS_OK or
 * AHT_DNS_FAILED. Everything above this line is the production path
 * whichever function is installed, so a test that replaces only the
 * lookup still exercises the waiting, the deadline and the handoff. */
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
        char *slot = job->addrs[job->count];
        /* The address bytes are in network order in the sockaddr,
         * which is the order both formatters read them in. */
        if (p->ai_family == AF_INET)
            aht_fmt_ipv4((const unsigned char *)
                         &((struct sockaddr_in *) p->ai_addr)->sin_addr,
                         slot, AHT_DNS_ADDRSTRLEN);
        else if (p->ai_family == AF_INET6)
            aht_fmt_ipv6((const unsigned char *)
                         &((struct sockaddr_in6 *) p->ai_addr)->sin6_addr,
                         slot, AHT_DNS_ADDRSTRLEN);
        else
            continue;

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
#ifdef _WIN32
        if (job->done_ev != NULL)
            CloseHandle(job->done_ev);
#else
        AHT_COND_FINI(&job->cv);
#endif
        AHT_MUTEX_FINI(&job->m);
        free(job);
    }
}

#ifdef _WIN32
static unsigned __stdcall
aht_dns_worker(void *arg)
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
#ifndef _WIN32
    AHT_COND_SIGNAL(&job->cv);
#endif
    AHT_UNLOCK(&job->m);

#ifdef _WIN32
    /* Signalled after the lock is dropped: the event carries no state
     * of its own, so the waiter has to re-read done under the lock
     * anyway, and setting it here keeps the critical section to the
     * publish. The job is still alive because this thread holds a
     * reference until the release below. */
    SetEvent(job->done_ev);
#endif

    aht_job_release(job);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* Wait for the worker to publish done, or for the budget to run out.
 * Returns with the lock held in neither case; the caller takes it to
 * read the result, and a worker that finishes in that gap is read as
 * the success it is. */
static void
aht_wait_for_done(aht_dns_job *job, long timeout_ms, aht_tick start)
{
#ifdef _WIN32
    DWORD ms;

    if (timeout_ms < 0) {
        ms = INFINITE;
    } else {
        unsigned long elapsed = aht_elapsed_ms(start);
        ms = (elapsed >= (unsigned long) timeout_ms)
             ? 0
             : (DWORD) ((unsigned long) timeout_ms - elapsed);
    }

    /* No predicate loop: a Win32 wait does not wake spuriously, and
     * the event is manual-reset and set exactly once, so this returns
     * either because done was published or because the budget ran
     * out. */
    WaitForSingleObject(job->done_ev, ms);
#else
    AHT_LOCK(&job->m);
    while (!job->done) {
        if (timeout_ms < 0) {
            pthread_cond_wait(&job->cv, &job->m);
        } else {
            unsigned long elapsed = aht_elapsed_ms(start);
            unsigned long remaining;
            struct timespec ts;

            if (elapsed >= (unsigned long) timeout_ms)
                break;
            remaining = (unsigned long) timeout_ms - elapsed;

            /* Darwin has no pthread_condattr_setclock, but its relative
             * wait is independent of wall-clock changes. Other POSIX
             * systems use an absolute timeout on the monotonic clock given
             * to the condvar in aht_dns_resolve. Recompute either form each
             * pass so a wakeup that is neither done nor the deadline cannot
             * extend the budget. */
#ifdef __APPLE__
            ts.tv_sec  = (time_t) (remaining / 1000UL);
            ts.tv_nsec = (long) ((remaining % 1000UL) * 1000000UL);
            pthread_cond_timedwait_relative_np(&job->cv, &job->m, &ts);
#else
            clock_gettime(CLOCK_MONOTONIC, &ts);
            ts.tv_sec  += (time_t) (remaining / 1000UL);
            ts.tv_nsec += (long) ((remaining % 1000UL) * 1000000UL);
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec  += 1;
                ts.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&job->cv, &job->m, &ts);
#endif
        }
    }
    AHT_UNLOCK(&job->m);
#endif
}

#ifdef _WIN32
/* getaddrinfo needs Winsock started, and a resolve can be the first
 * thing a program does; WSAStartup is reference-counted. By hand
 * because InitOnceExecuteOnce is Vista+: 0 -> 1 is won by one
 * caller, which starts Winsock and publishes 2; whoever finds 1
 * waits for that publish. The spin is bounded by one WSAStartup. */
static volatile LONG aht_wsa_once = 0;

static void
aht_wsa_ensure(void)
{
    if (InterlockedCompareExchange(&aht_wsa_once, 1, 0) == 0) {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
        InterlockedExchange(&aht_wsa_once, 2);
    } else {
        while (InterlockedCompareExchange(&aht_wsa_once, 2, 2) != 2)
            Sleep(0);
    }
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
    aht_tick start;

    if (host == NULL || out == NULL || count == NULL || max_addrs <= 0)
        return AHT_DNS_INTERNAL;

    *count = 0;

#ifdef _WIN32
    aht_wsa_ensure();
#endif

    job = (aht_dns_job *) calloc(1, sizeof *job);
    if (job == NULL)
        return AHT_DNS_INTERNAL;

    strncpy(job->host, host, sizeof job->host - 1);
    strncpy(job->svc, svc != NULL ? svc : "", sizeof job->svc - 1);
    job->status = AHT_DNS_FAILED;

    AHT_MUTEX_INIT(&job->m);
#ifdef _WIN32
    job->done_ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (job->done_ev == NULL) {
        AHT_MUTEX_FINI(&job->m);
        free(job);
        return AHT_DNS_INTERNAL;
    }
#else
#ifdef __APPLE__
    /* Darwin supplies only its default condition-variable clock; timed
     * waits use pthread_cond_timedwait_relative_np above instead. */
    pthread_cond_init(&job->cv, NULL);
#else
    {
        /* Monotonic, to match aht_elapsed_ms and the absolute deadline
         * pthread_cond_timedwait is given. */
        pthread_condattr_t a;
        pthread_condattr_init(&a);
        pthread_condattr_setclock(&a, CLOCK_MONOTONIC);
        pthread_cond_init(&job->cv, &a);
        pthread_condattr_destroy(&a);
    }
#endif
#endif

    /* Both references exist before the worker does, so the worker can
     * never observe a count that has not yet counted it. */
    job->refs = 2;

    start = aht_tick_now();

#ifdef _WIN32
    {
        /* _beginthreadex and not CreateThread: the worker reaches the
         * C runtime (strncpy, snprintf, and whatever getaddrinfo does
         * underneath), and msvcrt sets up its per-thread state only
         * for threads it started itself. */
        uintptr_t t = _beginthreadex(NULL, 0, aht_dns_worker, job, 0, NULL);
        if (t == 0) {
            job->refs = 1;             /* no worker to give one back */
            aht_job_release(job);
            return AHT_DNS_INTERNAL;
        }
        CloseHandle((HANDLE) t);       /* detached */
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

    aht_wait_for_done(job, timeout_ms, start);

    AHT_LOCK(&job->m);
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
 * Not bound by AHT.DNS. The fake sleeps, then answers with canned
 * literals, so the timeout path is deterministic without a network.
 * aht_dns_fake_completions_for_test counts completions after the
 * wake, so a test can observe that an abandoned worker finished late
 * rather than assume it. */

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
        /* 127.0.0.1, 127.0.0.2, ...: distinct so a test can tell
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

/* Format addr (4 or 16 bytes in network order, per family 4 or 6)
 * into out. Returns 1 on success, 0 on a bad argument. Reachable
 * directly so the tests cover the longest-zero-run rule, its leftmost
 * tie-break, a run at either end and the v4-mapped shape, which a
 * lookup of localhost would not. */
int
aht_dns_format_for_test(int family, const unsigned char *addr,
                        char *out, int cap)
{
    if (addr == NULL || out == NULL || cap < AHT_DNS_ADDRSTRLEN)
        return 0;
    if (family == 4)
        aht_fmt_ipv4(addr, out, (size_t) cap);
    else if (family == 6)
        aht_fmt_ipv6(addr, out, (size_t) cap);
    else
        return 0;
    return 1;
}
