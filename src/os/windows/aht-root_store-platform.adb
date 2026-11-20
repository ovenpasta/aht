--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C.Strings;
with System;

with AHT.Bytes;

--  Windows: the current user's ROOT system store, opened with
--  CertOpenSystemStoreW. That logical store includes the local
--  machine's roots and those deployed by group policy. Every entry is
--  examined, and one is taken when it is X.509 and its enhanced key
--  usage (the extension intersected with the store's EKU property)
--  allows server authentication, so a root an administrator disabled
--  for that purpose is left out. The Disallowed store is not
--  consulted. Windows fetches some roots from Windows Update only
--  when a chain needs them, and enumeration sees only those already
--  installed. Every entry point exists on Windows XP.
package body AHT.Root_Store.Platform is

   --  Named even though GNAT's mingw link spec may already have it.
   pragma Linker_Options ("-lcrypt32");

   package IC renames Interfaces.C;

   use type IC.int;
   use type IC.unsigned_long;
   use type System.Address;

   --  DWORD and ULONG are 32 bits on both Windows widths (LLP64), as
   --  is unsigned long.
   subtype DWORD is IC.unsigned_long;
   subtype BOOL is IC.int;

   X509_ASN_ENCODING : constant DWORD := 16#0000_0001#;
   CRYPT_E_NOT_FOUND : constant DWORD := 16#8009_2004#;

   --  szOID_PKIX_KP_SERVER_AUTH.
   Server_Auth_OID : constant String := "1.3.6.1.5.5.7.3.1";

   --  Ceiling on the EKU structure CertGetEnhancedKeyUsage may ask
   --  for; a larger answer is treated as no usage.
   Max_Usage_Bytes : constant := 64 * 1024;

   --  CERT_CONTEXT.
   type Cert_Context is record
      Cert_Encoding_Type : DWORD;
      Cert_Encoded       : System.Address;   --  BYTE *
      Cert_Encoded_Size  : DWORD;
      Cert_Info          : System.Address;   --  PCERT_INFO
      Cert_Store         : System.Address;   --  HCERTSTORE
   end record
     with Convention => C;

   type Cert_Context_Access is access constant Cert_Context
     with Convention => C;

   --  CERT_ENHKEY_USAGE.
   type Enhkey_Usage is record
      Usage_Identifier_Count : DWORD;
      Usage_Identifiers      : System.Address;   --  LPSTR *
   end record
     with Convention => C;

   --  Stdcall throughout: the Win32 convention, identical to C on
   --  x86-64. On 32-bit x86 GNAT decorates a Stdcall External_Name
   --  with the argument bytes (_CertOpenSystemStoreW@8), as it does
   --  for RtlGenRandom in AHT.Random.Source; that link, and this body
   --  on either Windows target, has been compile-checked only (see
   --  docs/tls.md).

   --  HCRYPTPROV_LEGACY is ULONG_PTR, pointer-sized; 0 asks for the
   --  default provider.
   function CertOpenSystemStoreW
     (Prov                : IC.size_t;
      Subsystem_Protocol  : System.Address)   --  LPCWSTR
      return System.Address                   --  HCERTSTORE
     with Import, Convention => Stdcall,
          External_Name => "CertOpenSystemStoreW";

   --  Frees Prev and returns the next context, or null at the end.
   function CertEnumCertificatesInStore
     (Cert_Store         : System.Address;
      Prev_Cert_Context  : Cert_Context_Access)
      return Cert_Context_Access
     with Import, Convention => Stdcall,
          External_Name => "CertEnumCertificatesInStore";

   function CertFreeCertificateContext
     (Cert_Context : Cert_Context_Access) return BOOL
     with Import, Convention => Stdcall,
          External_Name => "CertFreeCertificateContext";

   function CertCloseStore
     (Cert_Store : System.Address;
      Flags      : DWORD) return BOOL
     with Import, Convention => Stdcall,
          External_Name => "CertCloseStore";

   function CertGetEnhancedKeyUsage
     (Cert_Context : Cert_Context_Access;
      Flags        : DWORD;
      Usage        : System.Address;          --  PCERT_ENHKEY_USAGE
      Usage_Size   : access DWORD) return BOOL
     with Import, Convention => Stdcall,
          External_Name => "CertGetEnhancedKeyUsage";

   function GetLastError return DWORD
     with Import, Convention => Stdcall,
          External_Name => "GetLastError";

   Root_Name : aliased constant IC.wchar_array :=
     IC.To_C (Wide_String'("ROOT"));

   --  True when Ctx may anchor a server certificate. A successful
   --  size query of 0, or an empty usage list with GetLastError
   --  reporting CRYPT_E_NOT_FOUND, means no restriction anywhere and
   --  every use; an empty list otherwise means no use. A failing call
   --  is no use. The identifier count is clamped to what fits in the
   --  buffer the API filled, and a null identifier is skipped.
   function Allows_Server_Auth (Ctx : Cert_Context_Access) return Boolean
   is
      Size : aliased DWORD := 0;
   begin
      if CertGetEnhancedKeyUsage (Ctx, 0, System.Null_Address, Size'Access)
           = 0
      then
         return False;
      end if;
      if Size = 0 then
         return True;
      end if;
      if Size > Max_Usage_Bytes then
         return False;
      end if;

      declare
         Word : constant Positive :=
           System.Word_Size / System.Storage_Unit;

         --  Words, so the buffer is aligned for the pointers in it.
         type Word_Array is array (1 .. (Natural (Size) + Word - 1) / Word)
           of System.Address;

         Buf   : Word_Array := [others => System.Null_Address];
         Usage : Enhkey_Usage with Import, Address => Buf'Address;

         Header_Bytes : constant Natural :=
           Enhkey_Usage'Size / System.Storage_Unit;
         Ptr_Bytes    : constant Positive :=
           IC.Strings.chars_ptr'Size / System.Storage_Unit;
         Filled       : Natural;
         Max_Count    : Natural;
         Count        : Natural;
      begin
         if Natural (Size) < Header_Bytes
           or else CertGetEnhancedKeyUsage (Ctx, 0, Buf'Address, Size'Access)
                     = 0
         then
            return False;
         end if;

         if Usage.Usage_Identifier_Count = 0 then
            --  Read before anything else can overwrite it.
            return GetLastError = CRYPT_E_NOT_FOUND;
         end if;

         --  Size now holds what the second call wrote. The count may
         --  claim no more pointers than that, and the buffer, hold.
         Filled :=
           Natural'Min (Natural (Size), Buf'Size / System.Storage_Unit);
         if Usage.Usage_Identifiers = System.Null_Address
           or else Filled < Header_Bytes
         then
            return False;
         end if;
         Max_Count := (Filled - Header_Bytes) / Ptr_Bytes;
         Count :=
           (if Usage.Usage_Identifier_Count > DWORD (Max_Count)
            then Max_Count
            else Natural (Usage.Usage_Identifier_Count));

         declare
            type OID_Array is array (1 .. Count) of IC.Strings.chars_ptr
              with Convention => C;
            OIDs : OID_Array with Import, Address => Usage.Usage_Identifiers;
            use type IC.Strings.chars_ptr;
         begin
            for OID of OIDs loop
               if OID /= IC.Strings.Null_Ptr
                 and then IC.Strings.Value (OID) = Server_Auth_OID
               then
                  return True;
               end if;
            end loop;
         end;
         return False;
      end;
   end Allows_Server_Auth;

   procedure Collect_Default (C : in out Collector) is
      Store  : System.Address;
      Ctx    : Cert_Context_Access := null;
      One    : Natural;
      Added  : Natural := 0;
      Ignore : BOOL;
   begin
      --  CertOpenSystemStoreW cannot raise; a null store is no store.
      Store := CertOpenSystemStoreW (0, Root_Name'Address);
      if Store = System.Null_Address then
         return;
      end if;

      --  Any failure inside (Storage_Error) ends the enumeration with
      --  Truncated set; the store is released either way and nothing
      --  propagates, per the contract of Load.
      begin
         loop
            Ctx := CertEnumCertificatesInStore (Store, Ctx);
            exit when Ctx = null;

            --  Leaving the enumeration early leaves Ctx referenced;
            --  it is freed below.
            exit when not Admit_Entry (C);

            if (Ctx.Cert_Encoding_Type and X509_ASN_ENCODING) /= 0
              and then Ctx.Cert_Encoded /= System.Null_Address
              and then Allows_Server_Auth (Ctx)
            then
               declare
                  DER : AHT.Bytes.Byte_Array
                    (1 .. Natural (Ctx.Cert_Encoded_Size))
                    with Import, Address => Ctx.Cert_Encoded;
               begin
                  Add_DER (C, DER, One);
                  Added := Added + One;
               end;
               exit when Full (C);
            end if;
         end loop;
      exception
         when others =>
            C.Result.Truncated := True;
      end;

      if Ctx /= null then
         Ignore := CertFreeCertificateContext (Ctx);
      end if;
      Ignore := CertCloseStore (Store, 0);

      if Added > 0 then
         Note_Location (C, "ROOT");
         C.Result.Origin := Native_Store;
      end if;
   end Collect_Default;

end AHT.Root_Store.Platform;
