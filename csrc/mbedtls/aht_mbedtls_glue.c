/*  Copyright (C) 2026 Aldo Nicolas Bruno
 *  SPDX-License-Identifier: Apache-2.0
 */

/* aht_mbedtls_glue.c - C glue for the Ada mbedTLS binding.
 *
 * The context structs (ssl, config, ctr_drbg, entropy, x509_crt)
 * have ABI- and configuration-dependent layouts (the posix archive
 * enables MBEDTLS_THREADING_C, the Windows one is threadless), so Ada
 * treats each as an opaque pointer and sizeof is computed here.
 * Also here: the two calls that pass mbedTLS's own function pointers.
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
 * because it is the only symbol crossing in this direction. */
extern int aht_mbedtls_entropy_poll(void *data, unsigned char *output,
                                    size_t len, size_t *olen);

/* The library is built MBEDTLS_NO_PLATFORM_ENTROPY, so the pool has
 * no sources and seeding would fail. The source registered here is
 * AHT.Random, which the rest of the library also draws from.
 * MBEDTLS_ENTROPY_BLOCK_SIZE is the number of bytes the pool takes
 * from a source before it counts as seeded; SOURCE_STRONG says the
 * source may be the only one. A failed registration is reported as
 * allocation failure: a context with no sources would defer the
 * report to mbedtls_ctr_drbg_seed. */
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
 * library's own entropy callback; passing a C function pointer is
 * simpler here than from Ada. No personalization string. */
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
