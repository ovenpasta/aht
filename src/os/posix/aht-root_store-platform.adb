--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  POSIX: the system bundle file, else the system certificate
--  directory, at the locations Go's crypto/x509 searches. macOS takes
--  this body too: /etc/ssl/cert.pem is its system bundle, which holds
--  the system roots and not the roots an administrator or user added
--  to the keychains.
package body AHT.Root_Store.Platform is

   function "+" (S : String) return SU.Unbounded_String
     renames SU.To_Unbounded_String;

   type Path_List is array (Positive range <>) of SU.Unbounded_String;

   --  In search order; the first that yields a certificate is used.
   --  Debian, Ubuntu, Gentoo, Arch; Fedora, RHEL 6; openSUSE;
   --  OpenELEC; CentOS, RHEL 7; Alpine, OpenBSD, macOS; FreeBSD;
   --  DragonFly; NetBSD.
   Bundle_Files : constant Path_List :=
     [+"/etc/ssl/certs/ca-certificates.crt",
      +"/etc/pki/tls/certs/ca-bundle.crt",
      +"/etc/ssl/ca-bundle.pem",
      +"/etc/pki/tls/cacert.pem",
      +"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
      +"/etc/ssl/cert.pem",
      +"/usr/local/etc/ssl/cert.pem",
      +"/usr/local/share/certs/ca-root-nss.crt",
      +"/etc/openssl/certs/ca-certificates.crt"];

   --  Consulted only when no bundle file yields a certificate.
   Cert_Dirs : constant Path_List :=
     [+"/etc/ssl/certs",
      +"/etc/pki/tls/certs"];

   procedure Collect_Default (C : in out Collector) is
      One : Natural;
   begin
      for F of Bundle_Files loop
         exit when Full (C);
         Add_File (C, SU.To_String (F), One);
         if One > 0 then
            Note_Location (C, SU.To_String (F));
            C.Result.Origin := Bundle_File;
            return;
         end if;
      end loop;

      for D of Cert_Dirs loop
         exit when Full (C);
         Add_Directory (C, SU.To_String (D), One);
         if One > 0 then
            Note_Location (C, SU.To_String (D));
            C.Result.Origin := Directory;
            return;
         end if;
      end loop;
   end Collect_Default;

end AHT.Root_Store.Platform;
