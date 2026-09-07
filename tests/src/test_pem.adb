--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  AHT.PEM envelope validation, in isolation: a pure string scanner,
--  fixture-free. It is the whole of the all-or-nothing guarantee,
--  since neither TLS backend can answer "was the input wholly what I
--  supplied?".
--
--  Cases:
--    - what a bundle may contain: ordinary text before or after a
--      valid certificate, which both backends accept silently
--    - index arithmetic: slices whose bounds sit near Positive'Last,
--      where absolute positions with a one-past-the-end marker
--      overflow into Constraint_Error

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.PEM;

procedure Test_PEM is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_pem: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   B : constant String := "-----BEGIN CERTIFICATE-----";
   E : constant String := "-----END CERTIFICATE-----";

   --  A syntactically complete block. The body is not real base64 and
   --  does not need to be: this validates the envelope, and says so.
   One : constant String := B & ASCII.LF & "QUJD" & ASCII.LF & E;

   --  The call is in the statement part. An exception raised while
   --  elaborating a declaration propagates OUT of the enclosing block,
   --  past that block's own handler, so a helper that computed the
   --  verdict in its declarative part could not report a raise.
   procedure Expect_OK (What : String; Data : String) is
   begin
      declare
         Problem : constant String := AHT.PEM.Bundle_Problem (Data);
      begin
         if Problem /= "" then
            Fail (What & ": rejected with " & Problem
                  & ", but this is a well-formed bundle");
         end if;
      end;
   exception
      when Ex : others =>
         Fail (What & ": raised "
               & Ada.Exceptions.Exception_Name (Ex)
               & " instead of returning a verdict");
   end Expect_OK;

   procedure Expect_Problem (What : String; Data : String) is
   begin
      declare
         Problem : constant String := AHT.PEM.Bundle_Problem (Data);
      begin
         if Problem = "" then
            Fail (What & ": accepted, but this is not a well-formed "
                  & "bundle");
         end if;
      end;
   exception
      when Ex : others =>
         Fail (What & ": raised "
               & Ada.Exceptions.Exception_Name (Ex)
               & " instead of returning a verdict");
   end Expect_Problem;

begin
   --  What a bundle may contain
   Expect_OK ("single", One);
   Expect_OK ("two", One & ASCII.LF & One);
   Expect_OK ("surrounding-whitespace",
              "  " & ASCII.LF & One & ASCII.LF & "  " & ASCII.HT);
   Expect_OK ("crlf",
              B & ASCII.CR & ASCII.LF & "QUJD" & ASCII.CR & ASCII.LF & E);

   Expect_Problem ("empty", "");
   Expect_Problem ("whitespace-only", "   " & ASCII.LF & ASCII.HT);
   Expect_Problem ("garbage-only", "not a certificate");

   --  Ordinary text around a valid block. Both backends accept these;
   --  the scanner is what rejects them.
   Expect_Problem ("trailing-text", One & ASCII.LF & "trailing junk");
   Expect_Problem ("leading-text", "leading junk" & ASCII.LF & One);

   Expect_Problem ("no-end", B & ASCII.LF & "QUJD");
   Expect_Problem ("nested-begin", B & ASCII.LF & B & ASCII.LF & E);
   Expect_Problem ("end-only", E);

   --  Index arithmetic

   --  A String need not start at 1. A scanner that assumes it does,
   --  or that mixes absolute positions with lengths, goes wrong here
   --  and nowhere else.
   declare
      Shifted : constant String (500 .. 499 + One'Length) := One;
   begin
      Expect_OK ("shifted-lower-bound", Shifted);
   end;

   declare
      Shifted : constant String (500 .. 499 + 12) := "not a cert!!";
   begin
      Expect_Problem ("shifted-garbage", Shifted);
   end;

   --  Bounds at the very top of Positive. The object is tiny; only
   --  its indices are extreme. Representing "one past the end" as an
   --  absolute position overflows here, a Constraint_Error in place
   --  of the promised diagnostic.
   declare
      High : constant String
        (Positive'Last - One'Length + 1 .. Positive'Last) := One;
   begin
      Expect_OK ("high-bounds-valid", High);
   end;

   declare
      High : constant String (Positive'Last - 11 .. Positive'Last) :=
        "not a cert!!";
   begin
      Expect_Problem ("high-bounds-garbage", High);
   end;

   --  Whitespace running to the last index: the scanner walks off the
   --  end without finding a marker, the most direct exercise of the
   --  one-past representation.
   declare
      High : constant String (Positive'Last - 3 .. Positive'Last) :=
        "    ";
   begin
      Expect_Problem ("high-bounds-whitespace", High);
   end;

   --  A bundle that is EXACTLY the BEGIN marker, ending at the last
   --  index. The marker comparison's slice endpoint is Data'First + O
   --  + M'Length - 1, evaluated left to right, so the intermediate
   --  sum reaches Positive'Last + 1; and once the marker is consumed
   --  the offset equals the length, so the tail slice's start
   --  overflows the same way.
   declare
      High : constant String
        (Positive'Last - B'Length + 1 .. Positive'Last) := B;
   begin
      Expect_Problem ("high-bounds-begin-only", High);
   end;

   --  The same with a leading space, so the whitespace skip runs
   --  first and the marker is reached at a non-zero offset.
   declare
      High : constant String
        (Positive'Last - B'Length .. Positive'Last) := " " & B;
   begin
      Expect_Problem ("high-bounds-space-then-begin", High);
   end;

   --  Trailing whitespace after a valid block, ending at the last
   --  index.
   declare
      High : constant String
        (Positive'Last - One'Length .. Positive'Last) := One & " ";
   begin
      Expect_OK ("high-bounds-trailing-space", High);
   end;

   if Failures = 0 then
      Put_Line ("test_pem: OK (envelope rules and index arithmetic)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_pem:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_PEM;
