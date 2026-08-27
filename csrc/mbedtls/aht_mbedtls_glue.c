/*
 * aht_mbedtls_glue.c — minimal C glue for the Ada mbedTLS binding.
 *
 * Why this exists: the mbedTLS context structs (ssl, config, ctr_drbg,
 * entropy, x509_crt) have layouts and sizes that depend on the target
 * ABI *and* the build configuration (our build enables
 * MBEDTLS_THREADING_C, which adds a mutex member). Hardcoding those
 * sizes — or modelling the structs — in Ada would break on any platform
 * whose layout differs from the box the bindings were generated on. So
 * Ada treats every context as an opaque pointer and the *target's* C
 * compiler computes sizeof here, where it is always correct.
 *
 * Scope is deliberately tiny:
 *   - per-context new/free (where sizeof matters), and
 *   - the two calls that pass mbedTLS's own function pointers
 *     (mbedtls_entropy_func, mbedtls_ctr_drbg_random), which is naturally
 *     C's job.
 * Every other mbedTLS operation is bound directly from Ada against these
 * opaque handles — function signatures are ABI-stable, struct layouts
 * are not.
 */

#include <stdlib.h>

#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"

void *aht_mbedtls_ssl_new(void)
{
    mbedtls_ssl_context *c = malloc(sizeof *c);
    if (c) mbedtls_ssl_init(c);
    return c;
}

void aht_mbedtls_ssl_free(void *c)
{
    if (!c) return;
    mbedtls_ssl_free((mbedtls_ssl_context *) c);
    free(c);
}

void *aht_mbedtls_config_new(void)
{
    mbedtls_ssl_config *c = malloc(sizeof *c);
    if (c) mbedtls_ssl_config_init(c);
    return c;
}

void aht_mbedtls_config_free(void *c)
{
    if (!c) return;
    mbedtls_ssl_config_free((mbedtls_ssl_config *) c);
    free(c);
}

void *aht_mbedtls_ctr_drbg_new(void)
{
    mbedtls_ctr_drbg_context *c = malloc(sizeof *c);
    if (c) mbedtls_ctr_drbg_init(c);
    return c;
}

void aht_mbedtls_ctr_drbg_free(void *c)
{
    if (!c) return;
    mbedtls_ctr_drbg_free((mbedtls_ctr_drbg_context *) c);
    free(c);
}

/* AHT.Mbedtls.Entropy.Poll. Declared here rather than in a header
 * because it is the only symbol crossing in this direction, and a
 * header for one extern would be a file to keep in step by hand. */
extern int aht_mbedtls_entropy_poll(void *data, unsigned char *output,
                                    size_t len, size_t *olen);

/* The library is built MBEDTLS_NO_PLATFORM_ENTROPY, so entropy_poll.c
 * contributes nothing and mbedtls_entropy_init leaves the pool with no
 * sources at all -- seeding would fail rather than fall back. The
 * source registered here is AHT.Random, which is also what the rest of
 * the library draws masks and nonces from.
 *
 * MBEDTLS_ENTROPY_BLOCK_SIZE is the number of bytes the pool must take
 * from this source before it considers itself seeded; SOURCE_STRONG
 * says the source is fit to be the only one, which here it is.
 *
 * A failed registration is reported as allocation failure. The
 * alternative -- returning a context with no sources -- defers the
 * report to mbedtls_ctr_drbg_seed, which cannot say which of several
 * things went wrong. */
void *aht_mbedtls_entropy_new(void)
{
    mbedtls_entropy_context *c = malloc(sizeof *c);
    if (!c) return NULL;
    mbedtls_entropy_init(c);
    if (mbedtls_entropy_add_source(c, aht_mbedtls_entropy_poll, NULL,
                                   MBEDTLS_ENTROPY_BLOCK_SIZE,
                                   MBEDTLS_ENTROPY_SOURCE_STRONG) != 0) {
        mbedtls_entropy_free(c);
        free(c);
        return NULL;
    }
    return c;
}

void aht_mbedtls_entropy_free(void *c)
{
    if (!c) return;
    mbedtls_entropy_free((mbedtls_entropy_context *) c);
    free(c);
}

void *aht_mbedtls_x509_crt_new(void)
{
    mbedtls_x509_crt *c = malloc(sizeof *c);
    if (c) mbedtls_x509_crt_init(c);
    return c;
}

void aht_mbedtls_x509_crt_free(void *c)
{
    if (!c) return;
    mbedtls_x509_crt_free((mbedtls_x509_crt *) c);
    free(c);
}

/* Seed CTR_DRBG from the entropy source. mbedtls_entropy_func is the
 * library's own entropy callback; passing it (a C function pointer) is
 * cleaner here than from Ada. No personalization string. */
int aht_mbedtls_ctr_drbg_seed(void *ctr_drbg, void *entropy)
{
    return mbedtls_ctr_drbg_seed((mbedtls_ctr_drbg_context *) ctr_drbg,
                                 mbedtls_entropy_func, entropy, NULL, 0);
}

/* Wire the config's RNG to CTR_DRBG. mbedtls_ctr_drbg_random is the
 * library's own RNG callback. */
void aht_mbedtls_conf_rng(void *conf, void *ctr_drbg)
{
    mbedtls_ssl_conf_rng((mbedtls_ssl_config *) conf,
                         mbedtls_ctr_drbg_random, ctr_drbg);
}
