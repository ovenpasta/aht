--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  AHT.Root_Store.Load, without a handshake: what it reads, from
--  where, and what it leaves out. Needs only the certificates
--  scripts/generate_cert.sh writes; no fixture is dialled (handshakes
--  are test_tls_trust's). Writes its inputs under
--  tests/obj/root_store_files. Run from the repo root.
--
--  Cases:
--    1. platform default (both variables cleared): a non-empty store
--       from the platform's own source, every block well-formed
--    2. SSL_CERT_FILE at the fixture certificate: exactly that
--       certificate, byte for byte
--    3. a bundle with comments, a duplicate, a TRUSTED CERTIFICATE
--       block, a non-base64 block and an unclosed block: only the
--       two distinct certificates
--    4. an empty file, a file of text, a missing file: nothing, and
--       no fallback to the platform default
--    5. SSL_CERT_DIR naming two directories: their files merged,
--       duplicates and non-PEM files dropped
--    6. both variables set: both read
--    7. Max_Certificates: one distinct block past the limit sets
--       Truncated and keeps exactly the limit
--    8. Max_Bytes: a file larger than the budget is not read
--    9. Max_Block_Bytes: a block body of exactly the limit is taken,
--       one past it is skipped, and a 10 MiB block is skipped without
--       raising (a body-sized local would exhaust the stack)
--   10. 300 000 BEGIN lines and one END: one pass, not one rescan per
--       BEGIN; bounded by wall time, generously
--
--  Not covered: Max_Entries, which would need 16 385 files; it is
--  the same counter-and-flag shape as the two limits that are.

with Ada.Calendar;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Streams.Stream_IO;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with GNAT.OS_Lib;

with AHT.Bytes;
with AHT.PEM;
with AHT.Root_Store;

procedure Test_Root_Store is

   package RS renames AHT.Root_Store;
   package Env renames Ada.Environment_Variables;

   use type RS.Origin_Kind;

   Fixture : constant String := "tests/server/certs/server.crt";
   Other   : constant String := "tests/server/certs/other.crt";
   Work    : constant String := "tests/obj/root_store_files";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_root_store: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Read_File (Path : String) return String is
      F : File_Type;
      R : Unbounded_String;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         Append (R, Get_Line (F));
         Append (R, ASCII.LF);
      end loop;
      Close (F);
      return To_String (R);
   exception
      when others =>
         if Is_Open (F) then
            Close (F);
         end if;
         return "";
   end Read_File;

   --  Written through Stream_IO so the bytes are exactly Data on every
   --  OS (Text_IO would write CR LF on Windows).
   procedure Write_File (Path : String; Data : String) is
      package SIO renames Ada.Streams.Stream_IO;
      F : SIO.File_Type;
   begin
      SIO.Create (F, SIO.Out_File, Path);
      String'Write (SIO.Stream (F), Data);
      SIO.Close (F);
   end Write_File;

   function Count_Of (Haystack, Needle : String) return Natural is
     (Ada.Strings.Fixed.Count (Haystack, Needle));

   function Contains (Haystack, Needle : String) return Boolean is
     (Ada.Strings.Fixed.Index (Haystack, Needle) /= 0);

   procedure Set_Env (File, Dir : String) is
   begin
      if File = "" then
         Env.Clear ("SSL_CERT_FILE");
      else
         Env.Set ("SSL_CERT_FILE", File);
      end if;
      if Dir = "" then
         Env.Clear ("SSL_CERT_DIR");
      else
         Env.Set ("SSL_CERT_DIR", Dir);
      end if;
   end Set_Env;

   --  The checks every non-empty result must pass: the block count
   --  agrees with Count, and the envelope is what the backends accept.
   procedure Check_Shape (What : String; R : RS.Roots) is
      PEM : constant String := To_String (R.PEM);
   begin
      if Count_Of (PEM, "-----BEGIN CERTIFICATE-----") /= R.Count then
         Fail (What & ": Count =" & R.Count'Image & " but the PEM holds"
               & Count_Of (PEM, "-----BEGIN CERTIFICATE-----")'Image
               & " blocks");
      end if;
      if R.Count > 0 and then AHT.PEM.Bundle_Problem (PEM) /= "" then
         Fail (What & ": the PEM fails AHT.PEM: "
               & AHT.PEM.Bundle_Problem (PEM));
      end if;
      if R.Count = 0
        and then (R.Origin /= RS.None or else Length (R.Location) /= 0
                  or else Length (R.PEM) /= 0)
      then
         Fail (What & ": nothing found, but Origin = " & R.Origin'Image
               & ", Location = """ & To_String (R.Location) & """");
      end if;
   end Check_Shape;

   procedure Expect
     (What      : String;
      R         : RS.Roots;
      Count     : Natural;
      Origin    : RS.Origin_Kind;
      Truncated : Boolean := False) is
   begin
      Check_Shape (What, R);
      if R.Count /= Count then
         Fail (What & ": Count =" & R.Count'Image & ", expected"
               & Count'Image);
      end if;
      if R.Origin /= Origin then
         Fail (What & ": Origin = " & R.Origin'Image & ", expected "
               & Origin'Image);
      end if;
      if R.Truncated /= Truncated then
         Fail (What & ": Truncated = " & R.Truncated'Image);
      end if;
   end Expect;

   --  A syntactically valid block whose body is the base64 of N's
   --  image: distinct per N. Load does not parse DER, so these count
   --  as certificates for the limit.
   function Fake_Block (N : Natural) return String is
     ("-----BEGIN CERTIFICATE-----" & ASCII.LF
      & AHT.Bytes.Base64_Encode
          (AHT.Bytes.From_String ("not a certificate" & N'Image))
      & ASCII.LF & "-----END CERTIFICATE-----" & ASCII.LF);

   Cert       : constant String := Read_File (Fixture);
   Other_Cert : constant String := Read_File (Other);
   Sep        : constant Character := GNAT.OS_Lib.Path_Separator;

begin
   if Cert = "" or else Other_Cert = ""
     or else not Contains (Cert, "-----BEGIN CERTIFICATE-----")
   then
      Fail ("cannot read " & Fixture & " and " & Other
            & "; run scripts/generate_cert.sh from the repo root");
      Put_Line ("test_root_store:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;

   if Ada.Directories.Exists (Work) then
      Ada.Directories.Delete_Tree (Work);
   end if;
   Ada.Directories.Create_Path (Work & "/a");
   Ada.Directories.Create_Path (Work & "/b");

   --  Case 1: the platform default. Every supported platform keeps a
   --  store, so empty is a failure, not a skip.
   Set_Env ("", "");
   declare
      R : constant RS.Roots := RS.Load;
   begin
      Check_Shape ("default", R);
      if R.Count = 0 then
         Fail ("default: the platform store yielded no certificate");
      elsif R.Origin not in RS.Bundle_File | RS.Directory | RS.Native_Store
      then
         Fail ("default: Origin = " & R.Origin'Image);
      elsif Length (R.Location) = 0 then
         Fail ("default: Location is empty");
      end if;
      if R.Truncated then
         Fail ("default: Truncated with" & R.Count'Image & " certificates");
      end if;
      Put_Line ("test_root_store: platform default:" & R.Count'Image
                & " certificates from " & R.Origin'Image & " "
                & To_String (R.Location));
   end;

   --  Case 2: SSL_CERT_FILE at the fixture. generate_cert.sh writes
   --  64-column PEM with LF line ends, which is Load's own output
   --  form, so the result is the file byte for byte.
   Set_Env (Fixture, "");
   declare
      R : constant RS.Roots := RS.Load;
   begin
      Expect ("cert-file", R, 1, RS.Environment);
      if To_String (R.PEM) /= Cert then
         Fail ("cert-file: the PEM is not the fixture certificate");
      end if;
      if To_String (R.Location) /= Fixture then
         Fail ("cert-file: Location = """ & To_String (R.Location) & """");
      end if;
   end;

   --  Case 3: what a real bundle carries besides certificates. The
   --  fixture twice, once with CR LF line ends and indented, so the
   --  duplicate is caught on content rather than on bytes.
   declare
      CRLF_Cert : Unbounded_String;
   begin
      for Ch of Cert loop
         if Ch = ASCII.LF then
            Append (CRLF_Cert, ASCII.CR & ASCII.LF & "  ");
         else
            Append (CRLF_Cert, Ch);
         end if;
      end loop;

      Write_File
        (Work & "/mixed.pem",
         "# Mozilla bundle comment" & ASCII.LF
         & Cert
         & "Subject: CN=localhost" & ASCII.LF
         & To_String (CRLF_Cert)
         & "-----BEGIN TRUSTED CERTIFICATE-----" & ASCII.LF
         & "QUJD" & ASCII.LF
         & "-----END TRUSTED CERTIFICATE-----" & ASCII.LF
         & "-----BEGIN CERTIFICATE-----" & ASCII.LF
         & "not*base64!" & ASCII.LF
         & "-----END CERTIFICATE-----" & ASCII.LF
         & "-----BEGIN CERTIFICATE-----" & ASCII.LF
         & "QUJD" & ASCII.LF
         & Other_Cert
         & "trailing text" & ASCII.LF);
   end;
   Set_Env (Work & "/mixed.pem", "");
   declare
      R : constant RS.Roots := RS.Load;
   begin
      Expect ("mixed", R, 2, RS.Environment);
      if To_String (R.PEM) /= Cert & Other_Cert then
         Fail ("mixed: the PEM is not the two certificates in order");
      end if;
   end;

   --  Case 4: nothing usable. With SSL_CERT_FILE set, the platform
   --  default is not consulted, so case 1 having found a store makes
   --  an empty result here the evidence.
   Write_File (Work & "/empty.pem", "");
   Write_File (Work & "/text.pem", "no certificates here" & ASCII.LF);
   declare
      type Path_List is array (Positive range <>) of Unbounded_String;
      Paths : constant Path_List :=
        [To_Unbounded_String (Work & "/empty.pem"),
         To_Unbounded_String (Work & "/text.pem"),
         To_Unbounded_String (Work & "/missing.pem"),
         To_Unbounded_String (Work & "/a")];
   begin
      for Path of Paths loop
         Set_Env (To_String (Path), "");
         Expect ("nothing (" & To_String (Path) & ")", RS.Load, 0,
                 RS.None);
      end loop;
   end;

   --  Case 5: two directories. a holds the fixture and a text file; b
   --  holds the fixture again (another name), the other certificate
   --  and a DER-looking binary.
   Write_File (Work & "/a/server.pem", Cert);
   Write_File (Work & "/a/README", "not a certificate" & ASCII.LF);
   Write_File (Work & "/b/0001.0", Cert);
   Write_File (Work & "/b/other.pem", Other_Cert);
   Write_File (Work & "/b/root.cer", [ASCII.ESC, ASCII.NUL, 'x']);
   Set_Env ("", Work & "/a" & Sep & Work & "/b" & Sep);
   declare
      R : constant RS.Roots := RS.Load;
   begin
      Expect ("cert-dir", R, 2, RS.Environment);
      if To_String (R.Location) /= Work & "/a" & Sep & Work & "/b" then
         Fail ("cert-dir: Location = """ & To_String (R.Location) & """");
      end if;
   end;

   --  Case 6: both variables. The file holds only the fixture and the
   --  directory a only the fixture too, so the other certificate can
   --  only have come from b.
   Set_Env (Fixture, Work & "/b");
   Expect ("file+dir", RS.Load, 2, RS.Environment);

   --  Case 7: Max_Certificates. One distinct block past the limit.
   declare
      Many : Unbounded_String;
   begin
      for N in 1 .. RS.Max_Certificates + 1 loop
         Append (Many, Fake_Block (N));
      end loop;
      Write_File (Work & "/many.pem", To_String (Many));
   end;
   Set_Env (Work & "/many.pem", "");
   Expect ("max-certificates", RS.Load, RS.Max_Certificates,
           RS.Environment, Truncated => True);

   --  And exactly at the limit, it is not truncated.
   declare
      Many : Unbounded_String;
   begin
      for N in 1 .. RS.Max_Certificates loop
         Append (Many, Fake_Block (N));
      end loop;
      Write_File (Work & "/limit.pem", To_String (Many));
   end;
   Set_Env (Work & "/limit.pem", "");
   Expect ("at-max-certificates", RS.Load, RS.Max_Certificates,
           RS.Environment);

   --  Case 8: Max_Bytes. A valid certificate padded with text past the
   --  budget: had the file been read, the certificate would count.
   declare
      package SIO renames Ada.Streams.Stream_IO;
      F   : SIO.File_Type;
      Pad : constant String (1 .. 64 * 1024) := [others => '#'];
   begin
      SIO.Create (F, SIO.Out_File, Work & "/huge.pem");
      String'Write (SIO.Stream (F), Cert);
      for I in 1 .. RS.Max_Bytes / Pad'Length loop
         String'Write (SIO.Stream (F), Pad);
      end loop;
      SIO.Close (F);
   end;
   Set_Env (Work & "/huge.pem", "");
   Expect ("max-bytes", RS.Load, 0, RS.None, Truncated => True);

   --  Case 9: Max_Block_Bytes. Bodies of 'A', which is base64; Load
   --  does not parse DER. No line breaks, so the body is exactly the
   --  span between the markers.
   declare
      B : constant String := "-----BEGIN CERTIFICATE-----";
      E : constant String := "-----END CERTIFICATE-----";
   begin
      Write_File (Work & "/at-limit.pem",
                  B & String'(1 .. RS.Max_Block_Bytes => 'A') & E);
      Set_Env (Work & "/at-limit.pem", "");
      Expect ("block-at-limit", RS.Load, 1, RS.Environment);

      Write_File (Work & "/past-limit.pem",
                  B & String'(1 .. RS.Max_Block_Bytes + 4 => 'A') & E
                  & Cert);
      Set_Env (Work & "/past-limit.pem", "");
      declare
         R : constant RS.Roots := RS.Load;
      begin
         Expect ("block-past-limit", R, 1, RS.Environment);
         if To_String (R.PEM) /= Cert then
            Fail ("block-past-limit: kept something other than the "
                  & "fixture");
         end if;
      end;

      declare
         package SIO renames Ada.Streams.Stream_IO;
         F     : SIO.File_Type;
         Chunk : constant String (1 .. 64 * 1024) := [others => 'A'];
      begin
         SIO.Create (F, SIO.Out_File, Work & "/huge-block.pem");
         String'Write (SIO.Stream (F), B);
         for I in 1 .. 160 loop
            String'Write (SIO.Stream (F), Chunk);
         end loop;
         String'Write (SIO.Stream (F), E & Cert);
         SIO.Close (F);
      end;
      Set_Env (Work & "/huge-block.pem", "");
      declare
         R : constant RS.Roots := RS.Load;
      begin
         Expect ("huge-block", R, 1, RS.Environment);
         if To_String (R.PEM) /= Cert then
            Fail ("huge-block: kept something other than the fixture");
         end if;
      end;
   end;

   --  Case 10: unclosed blocks. Each BEGIN line opens a block the next
   --  one abandons; only the fixture's own block closes. Rescanning to
   --  the END for every BEGIN is quadratic: hours at this size. One
   --  pass is well under a second; 60 s leaves room for a loaded or
   --  emulated host.
   declare
      package SIO renames Ada.Streams.Stream_IO;
      use type Ada.Calendar.Time;
      F       : SIO.File_Type;
      Line    : constant String := "-----BEGIN CERTIFICATE-----" & ASCII.LF;
      Started : Ada.Calendar.Time;
      Took    : Duration;
   begin
      SIO.Create (F, SIO.Out_File, Work & "/unclosed.pem");
      for I in 1 .. 300_000 loop
         String'Write (SIO.Stream (F), Line);
      end loop;
      String'Write (SIO.Stream (F), Cert);
      SIO.Close (F);

      Set_Env (Work & "/unclosed.pem", "");
      Started := Ada.Calendar.Clock;
      declare
         R : constant RS.Roots := RS.Load;
      begin
         Took := Ada.Calendar.Clock - Started;
         Expect ("unclosed", R, 1, RS.Environment);
         if To_String (R.PEM) /= Cert then
            Fail ("unclosed: kept something other than the fixture");
         end if;
      end;
      if Took > 60.0 then
         Fail ("unclosed: Load took" & Took'Image & " s");
      end if;
   end;

   Set_Env ("", "");
   Ada.Directories.Delete_Tree (Work);

   if Failures = 0 then
      Put_Line ("test_root_store: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_root_store:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;

exception
   when E : others =>
      Put_Line ("test_root_store: FAIL — unexpected "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (1);
end Test_Root_Store;
