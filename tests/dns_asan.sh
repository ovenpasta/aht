#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
# ASan/UBSan check for the reference-counted handoff in
# csrc/dns/aht_dns.c.
#
# Not part of run_tests.sh. It needs a sanitizer build of one
# translation unit, which is a different toolchain configuration from
# the library's, and wiring that into aht.gpr would add a build
# dimension to Aht.Variant for a check that is worth running when the
# shim changes rather than on every run.
#
# What it is for: test_dns proves the caller is bounded and that the
# abandoned worker completes, but neither of those observes the free.
# The interesting window is a worker finishing AFTER its caller has
# gone, where the last reference down must be the one that frees, and
# exactly once. This drives that window repeatedly under ASan, which
# is what turns a double free or a write into a freed job from silent
# corruption into a failure.
#
#   sh tests/dns_asan.sh

set -e

CC=${CC:-gcc}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

cat >"$OUT/driver.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ADDRSTRLEN 46
#define MAX_ADDRS  16

extern int  aht_dns_resolve(const char *host, const char *svc,
                            long timeout_ms, char *out, int max_addrs,
                            int *count);
extern void aht_dns_install_fake_for_test(int sleep_ms, int n_addrs);
extern void aht_dns_restore_real_for_test(void);
extern int  aht_dns_fake_completions_for_test(void);

/* Sleep without pulling in another threading header. */
static void nap_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long) (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

int main(void)
{
    char buf[MAX_ADDRS * ADDRSTRLEN];
    int  count, rc, i, before, waited;
    int  failures = 0;

    /* The abandoned-worker window, many times over. Each iteration
     * leaves a worker running past its caller; the free happens on
     * whichever side finishes last, which is what ASan is here to
     * watch. */
    for (i = 0; i < 50; i++) {
        aht_dns_install_fake_for_test(120, 2);
        before = aht_dns_fake_completions_for_test();

        rc = aht_dns_resolve("example.invalid", "443", 10,
                             buf, MAX_ADDRS, &count);
        if (rc != 1) {                      /* AHT_DNS_TIMEOUT */
            printf("iter %d: expected timeout, got %d\n", i, rc);
            failures++;
        }

        /* Wait for the worker so the free is inside the run rather
         * than racing process exit, where ASan would not see it. */
        for (waited = 0;
             aht_dns_fake_completions_for_test() == before && waited < 500;
             waited++)
            nap_ms(10);

        if (aht_dns_fake_completions_for_test() == before) {
            printf("iter %d: abandoned worker never completed\n", i);
            failures++;
        }
    }

    /* And the ordinary path, where the caller is last out. */
    for (i = 0; i < 50; i++) {
        aht_dns_install_fake_for_test(0, 3);
        rc = aht_dns_resolve("example.invalid", "443", 5000,
                             buf, MAX_ADDRS, &count);
        if (rc != 0 || count != 3) {
            printf("iter %d: expected 3 addrs, got rc=%d count=%d\n",
                   i, rc, count);
            failures++;
        }
        if (strcmp(buf, "127.0.0.1") != 0) {
            printf("iter %d: first addr = %s\n", i, buf);
            failures++;
        }
    }

    aht_dns_restore_real_for_test();

    if (failures) {
        printf("dns_asan: %d failure(s)\n", failures);
        return 1;
    }
    printf("dns_asan: OK (100 handoffs, both orderings)\n");
    return 0;
}
EOF

"$CC" -std=c11 -D_POSIX_C_SOURCE=200809L -g -O1 \
      -fsanitize=address,undefined -fno-omit-frame-pointer \
      -Wall -Wextra \
      csrc/dns/aht_dns.c "$OUT/driver.c" -o "$OUT/dns_asan" -pthread

ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$OUT/dns_asan"
