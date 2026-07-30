package AHT.Openssl is

   --  Root of the AHT.Openssl.* binding tree: the system OpenSSL 3
   --  (libssl/libcrypto). Children are curated hand-edits of the
   --  output of `scripts/regen_openssl_bindings.sh` (see docs/tls.md).
   --  Every OpenSSL handle (SSL_CTX*, SSL*, BIO*, X509_VERIFY_PARAM*)
   --  is already an opaque pointer at the C API level, so — unlike the
   --  mbedTLS backend — no sizing glue is needed; C glue exists only
   --  for the few macro-defined entry points (AHT.Openssl.Glue).
   --
   --  `pragma Linker_Options` here names the two system libraries. The
   --  pragma only fires when a binary transitively `with`s a unit in
   --  AHT.Openssl.*, so test binaries that don't touch TLS skip the
   --  link dependency. The library search path (-L) comes from
   --  aht.gpr's Linker_Options (AHT_OPENSSL_DIR, default /usr), so a
   --  Homebrew OpenSSL on macOS resolves too.
   pragma Linker_Options ("-lssl");
   pragma Linker_Options ("-lcrypto");

end AHT.Openssl;
