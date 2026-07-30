with Interfaces.C;
with Interfaces.C.Strings;

package body AHT.Openssl.Version is

   function C_Major return Interfaces.C.unsigned
     with Import, Convention => C, External_Name => "OPENSSL_version_major";
   function C_Minor return Interfaces.C.unsigned
     with Import, Convention => C, External_Name => "OPENSSL_version_minor";
   function C_Patch return Interfaces.C.unsigned
     with Import, Convention => C, External_Name => "OPENSSL_version_patch";

   --  const char *OpenSSL_version(int t); t = 0 is OPENSSL_VERSION,
   --  the full human-readable banner. The pointer is static storage.
   function C_Version
     (T : Interfaces.C.int) return Interfaces.C.Strings.chars_ptr
     with Import, Convention => C, External_Name => "OpenSSL_version";

   function Major return Natural is (Natural (C_Major));
   function Minor return Natural is (Natural (C_Minor));
   function Patch return Natural is (Natural (C_Patch));

   function Version_String return String is
     (Interfaces.C.Strings.Value (C_Version (0)));

end AHT.Openssl.Version;
