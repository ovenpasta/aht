--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  TLS concurrency stress (backend-neutral): one task floods large
--  binary messages over wss while the main task receives the echoes:
--  a sustained bidirectional load through ONE TLS session, forcing
--  outbound backpressure, partial drains and interleaved engine
--  access from two tasks (receiver task inside Read + sender inside
--  Write). Ordering and payload integrity must survive.
--
--  Fixture: tests/server/server_ws_tls.py (wss://localhost:8768,
--  websockets default max_size 1 MiB; payloads stay under that).

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes; use AHT.Bytes;
with AHT.Websocket.Client;

use type AHT.Bytes.Octet;

procedure Test_TLS_Stress is

   URL     : constant String := "wss://localhost:8768/";
   CA_File : constant String := "tests/server/certs/server.crt";

   Messages : constant := 8;
   Msg_Size : constant := 512_000;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_stress: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Deterministic per-message pattern, checkable at any index.
   function Pattern (Msg_No : Positive; Index : Positive) return Octet is
     (Octet ((Msg_No * 37 + Index) mod 251));

   WS : AHT.Websocket.Client.Client_Type;

   --  First sender-side error, if any (the sender is a separate task,
   --  so it cannot call Fail directly without a race on Failures).
   protected Sender_Status is
      procedure Note (Msg : String);
      function Message return String;
      function Failed return Boolean;
   private
      Has : Boolean := False;
      Txt : Unbounded_String;
   end Sender_Status;

   protected body Sender_Status is
      procedure Note (Msg : String) is
      begin
         if not Has then
            Has := True;
            Txt := To_Unbounded_String (Msg);
         end if;
      end Note;
      function Message return String is (To_String (Txt));
      function Failed return Boolean is (Has);
   end Sender_Status;

   type Payload_Access is access AHT.Bytes.Byte_Array;

begin
   WS.Connect (URL, Insecure => False, CA_Path => CA_File);

   declare
      task Sender;

      task body Sender is
         Payload : constant Payload_Access :=
           new AHT.Bytes.Byte_Array (1 .. Msg_Size);
      begin
         for M in 1 .. Messages loop
            for J in Payload'Range loop
               Payload (J) := Pattern (M, J);
            end loop;
            WS.Send_Binary (Payload.all);
         end loop;
      exception
         when E : others =>
            Sender_Status.Note
              (Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
      end Sender;

      Msg : AHT.Websocket.Client.Message_Type;
   begin
      for M in 1 .. Messages loop
         begin
            WS.Receive (Msg, Timeout => 60.0);
            if Msg.Payload.Length /= Msg_Size then
               Fail ("echo" & M'Image & ": length"
                     & Msg.Payload.Length'Image
                     & " (expected" & Integer'Image (Msg_Size) & ")");
            else
               --  Spot-check the pattern at the edges and middle.
               if Msg.Payload.Element (1) /= Pattern (M, 1)
                 or else Msg.Payload.Element (Msg_Size / 2)
                         /= Pattern (M, Msg_Size / 2)
                 or else Msg.Payload.Element (Msg_Size)
                         /= Pattern (M, Msg_Size)
               then
                  Fail ("echo" & M'Image & ": payload corrupted");
               end if;
            end if;
         exception
            when E : others =>
               Fail ("receive" & M'Image & ": "
                     & Ada.Exceptions.Exception_Name (E) & " — "
                     & Ada.Exceptions.Exception_Message (E));
               exit;
         end;
      end loop;
   end;  --  joins Sender

   if Sender_Status.Failed then
      Fail ("sender task: " & Sender_Status.Message);
   end if;

   begin
      WS.Close;
   exception
      when others => null;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_stress: OK ("
                & Messages'Image & " x" & Integer'Image (Msg_Size)
                & " bytes echoed bidirectionally)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_stress:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Stress;
