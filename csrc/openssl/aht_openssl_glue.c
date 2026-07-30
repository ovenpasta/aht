/* C glue for the OpenSSL backend — MACRO-defined entry points only.
 *
 * Unlike the mbedTLS glue (which exists to size config-dependent
 * structs), every OpenSSL handle is an opaque pointer, so the only
 * things Ada cannot import directly are the API entry points that the
 * headers define as macros over SSL_ctrl/SSL_CTX_ctrl/BIO_ctrl.
 * Wrapping them in real C functions is version-proof: the compiler
 * expands whatever the installed headers say, instead of Ada curating
 * ctrl numbers that could drift across OpenSSL releases.
 */

#include <openssl/ssl.h>
#include <openssl/bio.h>

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
