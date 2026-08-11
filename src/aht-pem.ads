--  Envelope validation for PEM certificate bundles.
--
--  This exists because neither TLS backend can be asked "was the
--  input wholly what I supplied?", and both were consulted on that
--  question and gave the wrong answer:
--
--    * OpenSSL's PEM_R_NO_START_LINE, the only signal available at
--      the end of a PEM_read_bio_X509 loop, means "no further header
--      found". Arbitrary trailing text produces it just as a clean
--      end of input does, so trailing garbage read as success.
--    * mbedTLS stops at the first missing header and returns the
--      count of certificates that FAILED, which for trailing garbage
--      is zero -- also success.
--
--  Both were verified before this was written. So the all-or-nothing
--  rule cannot be delegated to either library's error taxonomy; the
--  shape of the input has to be checked directly, once, in a place
--  both backends share.
--
--  Deliberately only the envelope. Whether the base64 inside a block
--  decodes to a certificate is the library's job and it does it well;
--  what it will not tell us is that something outside the blocks was
--  silently skipped.
package AHT.PEM is

   --  "" when Data is a well-formed bundle: one or more complete
   --  certificate blocks, with nothing but whitespace between, before
   --  and after them. Otherwise a diagnostic naming the problem.
   --
   --  Only the "CERTIFICATE" label is accepted. OpenSSL would also
   --  take "TRUSTED CERTIFICATE" and mbedTLS would not, and a bundle
   --  that verifies under one backend and not the other is worse than
   --  one refused by both.
   function Bundle_Problem (Data : String) return String;

end AHT.PEM;
