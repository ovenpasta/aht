with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.URL.Encoding;

procedure Test_URL_Encoding is

   Failures : Natural := 0;

   procedure Check (OK : Boolean; Message : String) is
   begin
      if not OK then
         Put_Line ("FAIL: " & Message);
         Failures := Failures + 1;
      end if;
   end Check;

   procedure Check_Eq (Got, Want, Label : String) is
   begin
      if Got /= Want then
         Put_Line
           ("FAIL " & Label & ": got [" & Got & "] want [" & Want & "]");
         Failures := Failures + 1;
      end if;
   end Check_Eq;

begin
   --  Unreserved (ASCII only!) passes through unchanged.
   Check_Eq (AHT.URL.Encoding.Percent_Encode ("abcDEF_-.~"),
             "abcDEF_-.~", "unreserved");

   --  Non-ASCII bytes (e.g. Latin-1 é = 0xE9) MUST be percent-encoded,
   --  even though Ada.Characters.Handling.Is_Alphanumeric would accept
   --  them as letters. This is the case the review flagged.
   Check_Eq (AHT.URL.Encoding.Percent_Encode
               ("" & Character'Val (16#E9#)),
             "%E9", "Latin-1 e-acute gets encoded");
   Check_Eq (AHT.URL.Encoding.Percent_Encode
               ("caf" & Character'Val (16#E9#)),
             "caf%E9", "mixed ASCII + non-ASCII");

   --  Space and punctuation get percent-encoded.
   Check_Eq (AHT.URL.Encoding.Percent_Encode ("a b/c"),
             "a%20b%2Fc", "space and slash");

   --  Round trip.
   declare
      Raw : constant String := "hello world & friends=yes?";
      Enc : constant String := AHT.URL.Encoding.Percent_Encode (Raw);
      Dec : constant String := AHT.URL.Encoding.Percent_Decode (Enc);
   begin
      Check_Eq (Dec, Raw, "percent round trip");
   end;

   --  Form encoding uses + for space.
   Check_Eq (AHT.URL.Encoding.Form_Encode ("a b"), "a+b", "form space");
   Check_Eq (AHT.URL.Encoding.Form_Decode ("a+b"), "a b", "form decode +");
   Check_Eq (AHT.URL.Encoding.Form_Decode ("a%20b"), "a b", "form decode %20");

   --  Invalid percent escape raises. The call must sit in a statement
   --  (not a declaration) for the local handler to catch it.
   begin
      if AHT.URL.Encoding.Percent_Decode ("bad%ZZ")'Length > 0 then
         Check (False, "should have raised on bad escape");
      end if;
   exception
      when Constraint_Error =>
         null;
   end;

   if Failures = 0 then
      Put_Line ("test_url_encoding: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_url_encoding: " & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_URL_Encoding;
