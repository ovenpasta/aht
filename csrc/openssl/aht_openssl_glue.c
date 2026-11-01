/*  Copyright (C) 2026 Aldo Nicolas Bruno
 *  SPDX-License-Identifier: Apache-2.0
 */

/* C glue for the OpenSSL backend.
 * Every OpenSSL handle is an opaque pointer, so no sizing glue is
 * needed. What Ada cannot import are the entry points the headers
 * define as macros over SSL_ctrl/SSL_CTX_ctrl/BIO_ctrl; wrapping them
 * here lets the installed headers supply the ctrl numbers.
 * aht_openssl_ctx_load_ca_pem needs ERR_GET_REASON and the PEM_R_/
 * X509_R_ reason codes, which also vary across releases.
 */

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/* SSL_set_tlsext_host_name (SNI). Macro over SSL_ctrl(...,
 * SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, ...).
 * Returns 1 on success. */
long
aht_openssl_set_tlsext_host_name(SSL *s, const char *name)
{
    return SSL_set_tlsext_host_name(s, (char *)name);
}

/* SSL_CTX_set_min_proto_version, macro over SSL_CTX_ctrl.
 * Returns 1 on success. */
long
aht_openssl_ctx_set_min_proto_version(SSL_CTX *ctx, int version)
{
    return SSL_CTX_set_min_proto_version(ctx, version);
}

/* Borrow, do not consume: a short/nonblocking send must retain its suffix. */
long
aht_openssl_peek_memory(BIO *b, char **data)
{
    return BIO_get_mem_data(b, data);
}

/* Stop SSL_read retrying across control records in one event-loop step.
 * Restore the original mode before returning: blocking Read is unchanged. */
int
aht_openssl_try_read(SSL *ssl, void *data, int len, int *error)
{
    const long mode = SSL_get_mode(ssl);
    SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);
    int ret = SSL_read(ssl, data, len);
    *error = ret > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl, ret);
    SSL_set_mode(ssl, mode);
    return ret;
}

/* BIO_set_mem_eof_return: -1 means retry, zero means hard TCP EOF. */
long
aht_openssl_set_mem_eof_return(BIO *b, long v)
{
    return BIO_set_mem_eof_return(b, v);
}

/* Load one or more concatenated PEM certificates into ctx's trust
 * store, all-or-nothing. A loop, because PEM_read_bio_X509 stops at
 * the first thing it cannot parse and would otherwise install the
 * certificates before the damage and report success.
 * Returns the number of certificates added (> 0), or:
 *   -1  allocation / no store
 *   -2  no certificate found at all
 *   -3  trailing or malformed data after the last certificate
 *   -4  a certificate could not be added to the store
 */
int
aht_openssl_ctx_load_ca_pem(SSL_CTX *ctx, const void *pem, int len)
{
    BIO        *bio;
    X509       *cert;
    X509_STORE *store;
    int         count = 0;
    unsigned long e;

    if (ctx == NULL || pem == NULL || len <= 0)
        return -1;

    store = SSL_CTX_get_cert_store(ctx);
    if (store == NULL)
        return -1;

    bio = BIO_new_mem_buf(pem, len);
    if (bio == NULL)
        return -1;

    /* Start from a clean queue: the peek below is how the loop's exit
     * reason is classified, and a stale entry would misclassify it. */
    ERR_clear_error();

    for (;;) {
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (cert == NULL)
            break;

        if (X509_STORE_add_cert(store, cert) != 1) {
            /* A duplicate is not a failure (bundles repeat roots), and
             * OpenSSL is not consistent across versions about
             * reporting one. Tolerate that, reject anything else. */
            if (ERR_GET_REASON(ERR_peek_last_error())
                != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                X509_free(cert);
                BIO_free(bio);
                return -4;
            }
            ERR_clear_error();
        }

        /* The store took its own reference. */
        X509_free(cert);
        count++;
    }

    /* A clean end of input leaves PEM_R_NO_START_LINE; anything else
     * is malformed input, refused even after a partial success. */
    e = ERR_peek_last_error();
    BIO_free(bio);

    if (ERR_GET_REASON(e) != PEM_R_NO_START_LINE)
        return -3;

    ERR_clear_error();

    if (count == 0)
        return -2;

    return count;
}
