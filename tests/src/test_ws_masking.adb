--  The masking key and the handshake nonce must be unpredictable.
--
--  RFC 6455 §5.3 requires the frame masking key to come from a strong
--  entropy source, and §4.1 requires Sec-WebSocket-Key to be a nonce
--  selected randomly per connection. Neither is about
--  confidentiality: masking exists so a client cannot be coerced into
--  emitting bytes a caching proxy would read as a second,
--  attacker-chosen HTTP request. A mask an observer can predict
--  defeats the purpose of masking entirely rather than weakening it,
--  and nothing about that is visible on the wire — which is why it
--  needs a test rather than a comment.
--
--  This is a property test, not a race test. It samples the source
--  and checks three things a broken one fails:
--
--    1. No repeats. The defect this replaced was a generator RESET on
--       every call, which draws from a clock seed — so two calls in
--       one tick returned identical bytes. Measured against the old
--       implementation this reports 4 collisions in 4096 draws; the
--       birthday expectation over 32 bits is 0.002, so the signal is
--       three orders of magnitude clear of the noise.
--    2. Not constant. A stub that filled with zeroes, or a source
--       that failed open, would pass a uniqueness check on a single
--       draw but not this.
--    3. Every byte value occurs. A source stuck in a narrow range —
--       ASCII, say — would still look unique at 32 bits.
--
--  It cannot prove unpredictability; nothing short of reading the
--  implementation can. What it does is fail loudly if the source is
--  ever swapped back for a PRNG.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes; use type AHT.Bytes.Octet;
with AHT.Random;

procedure Test_WS_Masking is

   Draws : constant := 4096;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_masking: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   type Mask is mod 2 ** 32;
   Seen : array (1 .. Draws) of Mask;

   Value_Seen : array (AHT.Bytes.Octet) of Boolean := [others => False];

   Nonzero : Boolean := False;
   Dupes   : Natural := 0;
   Missing : Natural := 0;

begin
   --  Draw masks the way Send_Frame does: four bytes, back to back,
   --  as a burst of frames on one connection would.
   for I in 1 .. Draws loop
      declare
         B : AHT.Bytes.Byte_Array (1 .. 4);
         V : Mask := 0;
      begin
         AHT.Random.Fill (B);
         for J in B'Range loop
            V := V * 256 + Mask (B (J));
            Value_Seen (B (J)) := True;
            if B (J) /= 0 then
               Nonzero := True;
            end if;
         end loop;
         Seen (I) := V;
      exception
         when E : others =>
            Fail ("drawing a mask raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
            Put_Line ("test_ws_masking:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;
   end loop;

   for I in 1 .. Draws loop
      for J in I + 1 .. Draws loop
         if Seen (I) = Seen (J) then
            Dupes := Dupes + 1;
         end if;
      end loop;
   end loop;

   --  Zero is the honest threshold. Over 32 bits and 4096 draws the
   --  expected count is 0.002, so a single repeat is already 500x the
   --  expectation and worth looking at rather than tolerating.
   if Dupes > 0 then
      Fail ("the source repeated a 4-byte mask" & Natural'Image (Dupes)
            & " time(s) in" & Natural'Image (Draws)
            & " draws — a strong source does not do that at this "
            & "sample size; a per-call generator reset does");
   end if;

   if not Nonzero then
      Fail ("every byte drawn was zero — the entropy source is not "
            & "producing anything");
   end if;

   for V in Value_Seen'Range loop
      if not Value_Seen (V) then
         Missing := Missing + 1;
      end if;
   end loop;

   if Missing > 0 then
      Fail (Natural'Image (Missing)
            & " of 256 byte values never appeared across"
            & Natural'Image (4 * Draws)
            & " bytes — the source is confined to a sub-range");
   end if;

   if Failures = 0 then
      Put_Line ("test_ws_masking: OK (" & Natural'Image (Draws)
                & " unique masks, full byte range)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_masking:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Masking;
