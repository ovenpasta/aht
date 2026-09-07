--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  AHT.PEM envelope validation, in isolation.
--
--  Fixture-free and pure: this is a string scanner, and every property
--  worth pinning is reachable without a socket. That matters because
--  the scanner is the whole of the all-or-nothing guarantee now --
--  neither TLS backend can answer "was the input wholly what I
--  supplied?", so if this is wrong, nothing downstream notices.
--
--  Two groups of cases.
--
--  The first is what a bundle may and may not contain. The interesting
--  ones are not the malformed blocks -- any implementation refuses
--  those -- but ORDINARY text before or after a perfectly valid
--  certificate, which both backends silently accepted before this
--  scanner existed.
--
--  The second is the index arithmetic, which is why this test is
--  separate rather than folded into the TLS test. A String in Ada is
--  not implicitly 1-based, and a scanner written with absolute
--  positions and a "one past the end" marker overflows on a slice
--  whose bounds sit near Positive'Last -- raising Constraint_Error
--  where it promised a diagnostic. The objects below are small; only
--  their BOUNDS are extreme, which is exactly the case that gets
--  missed.

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

   --  The call is in the STATEMENT part, deliberately. An exception
   --  raised while elaborating a declaration propagates OUT of the
   --  enclosing block, past that block's own handler -- so a helper
   --  that computed the verdict in its declarative part could not
   --  report a raise, and the whole run died instead. That is exactly
   --  what happened against the unfixed scanner.
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
   ---------------------------------------------------------------
   --  What a bundle may contain
   ---------------------------------------------------------------
   Expect_OK ("single", One);
   Expect_OK ("two", One & ASCII.LF & One);
   Expect_OK ("surrounding-whitespace",
              "  " & ASCII.LF & One & ASCII.LF & "  " & ASCII.HT);
   Expect_OK ("crlf",
              B & ASCII.CR & ASCII.LF & "QUJD" & ASCII.CR & ASCII.LF & E);

   Expect_Problem ("empty", "");
   Expect_Problem ("whitespace-only", "   " & ASCII.LF & ASCII.HT);
   Expect_Problem ("garbage-only", "not a certificate");

   --  The two that both backends accepted before this scanner
   --  existed. They are the reason it exists.
   Expect_Problem ("trailing-text", One & ASCII.LF & "trailing junk");
   Expect_Problem ("leading-text", "leading junk" & ASCII.LF & One);

   Expect_Problem ("no-end", B & ASCII.LF & "QUJD");
   Expect_Problem ("nested-begin", B & ASCII.LF & B & ASCII.LF & E);
   Expect_Problem ("end-only", E);

   ---------------------------------------------------------------
   --  Index arithmetic
   ---------------------------------------------------------------

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
   --  absolute position overflows here, which is a Constraint_Error
   --  in place of the promised diagnostic.
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
   --  end here rather than finding a marker, so it is the case that
   --  most directly exercises the one-past representation.
   declare
      High : constant String (Positive'Last - 3 .. Positive'Last) :=
        "    ";
   begin
      Expect_Problem ("high-bounds-whitespace", High);
   end;

   --  A bundle that is EXACTLY the BEGIN marker, ending at the last
   --  index. This is the sharpest form: the marker comparison's slice
   --  endpoint is Data'First + O + M'Length - 1, evaluated
   --  left-to-right, so the intermediate sum reaches Positive'Last + 1
   --  before the - 1 brings it back. And once the marker is consumed,
   --  the offset equals the length, so forming the tail slice's start
   --  overflows in the same way a second time.
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
