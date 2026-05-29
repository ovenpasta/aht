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

void *aht_mbedtls_entropy_new(void)
{
    mbedtls_entropy_context *c = malloc(sizeof *c);
    if (c) mbedtls_entropy_init(c);
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
