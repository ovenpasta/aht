/* C glue for the OpenSSL backend.
 *
 * Mostly MACRO-defined entry points. Unlike the mbedTLS glue (which
 * exists to size config-dependent structs), every OpenSSL handle is an
 * opaque pointer, so most of what Ada cannot import directly are the
 * API entry points the headers define as macros over
 * SSL_ctrl/SSL_CTX_ctrl/BIO_ctrl. Wrapping them in real C functions is
 * version-proof: the compiler expands whatever the installed headers
 * say, instead of Ada curating ctrl numbers that could drift across
 * OpenSSL releases.
 *
 * aht_openssl_ctx_load_ca_pem is here for the same reason rather than
 * that one: loading in-memory PEM needs ERR_GET_REASON and the
 * PEM_R_/X509_R_ reason codes, whose numeric values and masking are
 * exactly the sort of thing that drifts between releases. Doing the
 * loop in Ada would mean hard-coding 0x7FFFFF and 108 and hoping.
 */

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/* SSL_set_tlsext_host_name — SNI. Macro over SSL_ctrl(...,
 * SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, ...).
 * Returns 1 on success. */
long
aht_openssl_set_tlsext_host_name(SSL *s, const char *name)
{
    return SSL_set_tlsext_host_name(s, (char *)name);
}

/* SSL_CTX_set_min_proto_version — macro over SSL_CTX_ctrl.
 * Returns 1 on success. */
long
aht_openssl_ctx_set_min_proto_version(SSL_CTX *ctx, int version)
{
    return SSL_CTX_set_min_proto_version(ctx, version);
}

/* BIO_set_mem_eof_return — macro over BIO_ctrl. v = -1 makes an empty
 * memory-BIO read retryable (WANT_READ); v = 0 makes it EOF. The
 * engine starts the read BIO at -1 and flips it to 0 when the TCP
 * stream ends, so OpenSSL can tell "no data yet" from "stream over".
 */
long
aht_openssl_set_mem_eof_return(BIO *b, long v)
{
    return BIO_set_mem_eof_return(b, v);
}

/* Load one or more concatenated PEM certificates into ctx's trust
 * store, all-or-nothing.
 *
 * "All-or-nothing" is the contract and it is the whole reason this is
 * a loop rather than a single call: PEM_read_bio_X509 stops at the
 * first thing it cannot parse, so a bundle whose tail is truncated or
 * corrupt would otherwise install the certificates read before the
 * damage and report success. Trusting a prefix of what the caller
 * meant to trust is worse than trusting nothing, because nobody finds
 * out.
 *
 * Returns the number of certificates added (> 0) on full success, or:
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
            /* A duplicate is not a failure of the caller's intent --
             * bundles legitimately repeat a root -- and OpenSSL has
             * not been consistent across versions about whether it
             * reports one. Tolerate exactly that, reject anything
             * else. */
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

    /* Why did the loop stop? A clean end of input leaves
     * PEM_R_NO_START_LINE; anything else means the input was
     * malformed, and after a partial success that is precisely the
     * case this function exists to refuse. */
    e = ERR_peek_last_error();
    BIO_free(bio);

    if (ERR_GET_REASON(e) != PEM_R_NO_START_LINE)
        return -3;

    ERR_clear_error();

    if (count == 0)
        return -2;

    return count;
}
