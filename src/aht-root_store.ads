--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Strings.Unbounded;

private with Ada.Containers.Indefinite_Hashed_Sets;
private with Ada.Strings.Hash;
private with AHT.Bytes;

--  The platform's trust anchors as concatenated PEM, for CA_PEM or
--  for Use_System_Roots (AHT.Transport.TLS.Connect, which calls Load
--  itself). Nothing here verifies anything: Load reports what the
--  platform keeps, and the TLS backend parses it.
--
--  Search order, first rule that yields a certificate wins:
--    1. SSL_CERT_FILE and SSL_CERT_DIR, when either is set and not
--       empty. SSL_CERT_DIR is a list of directories separated by
--       GNAT.OS_Lib.Path_Separator (':' on POSIX, ';' on Windows).
--       Both are read and their certificates merged. When either is
--       set, only these are consulted, on every OS.
--    2. The platform default, one body per OS (AHT_OS in aht.gpr):
--       POSIX (Linux, the BSDs, macOS): the first well-known bundle
--       file that yields a certificate, else the first well-known
--       certificate directory that does; docs/tls.md lists them.
--       Windows: the current user's ROOT system store, which includes
--       the machine's roots, keeping only certificates whose enhanced
--       key usage allows server authentication.
--
--  Only "CERTIFICATE" PEM blocks are taken; text between blocks
--  (comments, "TRUSTED CERTIFICATE" blocks, DER files in a directory)
--  is ignored, and a block whose body is not base64 is skipped. The
--  output is re-wrapped at 64 columns and duplicates are dropped, so
--  it passes AHT.PEM.Bundle_Problem.
package AHT.Root_Store is

   package SU renames Ada.Strings.Unbounded;

   --  Limits on one Load. Reaching any of them stops the read and
   --  sets Truncated; what was read so far is kept.
   Max_Certificates : constant := 4_096;
   --  Distinct certificates in the result.
   Max_Bytes        : constant := 16 * 1024 * 1024;
   --  Bytes read from files, or DER bytes taken from the store. A
   --  file larger than what remains of the budget is not read.
   Max_Entries      : constant := 16_384;
   --  Files read plus store entries examined.

   --  Not a limit on the read: a PEM block whose body (the text
   --  between its BEGIN and END lines) is longer than this is skipped
   --  as malformed, before it is decoded. Real certificates are a few
   --  KiB.
   Max_Block_Bytes  : constant := 64 * 1024;

   type Origin_Kind is
     (None,          --  nothing yielded a certificate; PEM is empty
      Environment,   --  SSL_CERT_FILE and/or SSL_CERT_DIR
      Bundle_File,   --  a well-known bundle file (POSIX)
      Directory,     --  a well-known certificate directory (POSIX)
      Native_Store); --  the OS certificate store (Windows)

   type Roots is record
      PEM       : SU.Unbounded_String;
      --  Count CERTIFICATE blocks, LF line ends; empty when Count = 0.
      Count     : Natural := 0;
      Origin    : Origin_Kind := None;
      Location  : SU.Unbounded_String;
      --  What was read, for diagnostics: the file, the directories or
      --  the store name, several separated by Path_Separator. Empty
      --  when Origin is None.
      Truncated : Boolean := False;
      --  The read stopped before the end, at a limit above or on a
      --  failure other than a missing or unreadable source (memory
      --  exhausted); PEM is a subset of the store.
   end record;

   --  Reads the platform's trust anchors, per the search order above.
   --  Never raises. A missing, unreadable or malformed source is
   --  skipped; any other failure stops the read with Truncated set.
   --  Reads the environment and the filesystem or store on every
   --  call; nothing is cached, so a caller that dials often calls it
   --  once and passes PEM as CA_PEM.
   --
   --  Whoever controls SSL_CERT_FILE and SSL_CERT_DIR controls what
   --  this returns, and so what Use_System_Roots trusts.
   function Load return Roots;

private

   --  Certificate bodies already taken, base64 without whitespace.
   package Body_Sets is new Ada.Containers.Indefinite_Hashed_Sets
     (Element_Type        => String,
      Hash                => Ada.Strings.Hash,
      Equivalent_Elements => "=");

   --  The accumulator a Load fills; the platform body adds to it.
   type Collector is limited record
      Result     : Roots;
      Seen       : Body_Sets.Set;
      Bytes_Read : Natural := 0;
      Entries    : Natural := 0;
   end record;

   --  True once a limit has been reached; every Add is then a no-op.
   function Full (C : Collector) return Boolean is (C.Result.Truncated);

   --  Takes every well-formed CERTIFICATE block in Text, in one pass;
   --  a block not closed before the next BEGIN, or whose body exceeds
   --  Max_Block_Bytes, is skipped. Added is the number of new,
   --  distinct certificates. C is never left holding part of a
   --  block; a failure (Storage_Error) propagates.
   procedure Add_PEM_Text
     (C : in out Collector; Text : String; Added : out Natural);

   --  Takes one DER certificate, base64-encoded into a block. Counts
   --  against Max_Bytes; Added is 0 or 1.
   procedure Add_DER
     (C     : in out Collector;
      DER   : AHT.Bytes.Byte_Array;
      Added : out Natural);

   --  Reads one regular file (symbolic links followed) within the
   --  limits and takes its blocks. A path that is not a regular file
   --  adds nothing and is not counted; a regular file counts against
   --  Max_Entries, and one that cannot be read adds nothing. Any other
   --  failure sets Truncated. Never raises.
   procedure Add_File
     (C : in out Collector; Path : String; Added : out Natural);

   --  Every regular file directly in Dir (symbolic links followed),
   --  in name order. A missing or unreadable directory adds nothing;
   --  any other failure sets Truncated. Never raises.
   procedure Add_Directory
     (C : in out Collector; Dir : String; Added : out Natural);

   --  Counts one store entry against Max_Entries; False, with
   --  Truncated set, when the limit is reached.
   function Admit_Entry (C : in out Collector) return Boolean;

   --  Records a source that contributed into Location.
   procedure Note_Location (C : in out Collector; Where : String);

end AHT.Root_Store;
