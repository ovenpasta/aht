--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Autobahn|Testsuite client driver ("testee").
--
--  Drives the Autobahn fuzzingserver's client-test protocol against a
--  running server (default ws://127.0.0.1:9001, see run.sh for bringing
--  one up via Docker):
--
--    1. /getCaseCount        — server sends the case count as one text
--                              message, then closes.
--    2. /runCase?case=N&agent=A
--                            — server drives case N; we echo every data
--                              message back verbatim (text as text,
--                              binary as binary) until it closes. Control
--                              frames (ping/pong/close) are handled by the
--                              client itself. This echo behaviour is what
--                              Autobahn scores.
--    3. /updateReports?agent=A
--                            — server writes the HTML/JSON reports to the
--                              outdir from fuzzingserver.json.
--
--  Usage: aht_autobahn [BASE_URL] [AGENT]
--    BASE_URL defaults to ws://127.0.0.1:9001, AGENT to "AHT".
--
--  Each case runs on its own Client_Type in a declare block and is
--  always Closed before the block exits, so the per-connection receiver
--  task is joined (an abandoned client with a live task would hang at
--  scope exit). Each case is also wrapped so one failing case (e.g. a
--  Storage_Error on a multi-megabyte payload) does not abort the run.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Websocket;
with AHT.Websocket.Client;

procedure AHT_Autobahn is

   use type AHT.Websocket.Message_Kind;

   function Base_URL return String is
     (if Ada.Command_Line.Argument_Count >= 1
      then Ada.Command_Line.Argument (1)
      else "ws://127.0.0.1:9001");

   function Agent return String is
     (if Ada.Command_Line.Argument_Count >= 2
      then Ada.Command_Line.Argument (2)
      else "AHT");

   function Img (N : Integer) return String is
     (Ada.Strings.Fixed.Trim (N'Image, Ada.Strings.Left));

   function Get_Case_Count return Natural is
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
      N   : Natural := 0;
   begin
      AHT.Websocket.Client.Connect (C, Base_URL & "/getCaseCount");
      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 10.0);
         N := Natural'Value (Msg.Payload.To_String);
      exception
         when others => null;
      end;
      AHT.Websocket.Client.Close (C);
      return N;
   end Get_Case_Count;

   procedure Run_Case (N : Positive) is
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
      URL : constant String :=
        Base_URL & "/runCase?case=" & Img (N) & "&agent=" & Agent;
   begin
      begin
         AHT.Websocket.Client.Connect (C, URL);
      exception
         when E : others =>
            Put_Line ("  case " & Img (N) & ": connect failed: "
                      & Ada.Exceptions.Exception_Name (E));
            return;
      end;

      Echo : loop
         begin
            AHT.Websocket.Client.Receive (C, Msg, Timeout => 30.0);
         exception
            --  Closed_Error (server ended the case) or Timeout_Error
            --  (silent peer) both terminate the echo loop.
            when others => exit Echo;
         end;

         exit Echo when not AHT.Websocket.Client.Is_Open (C);

         begin
            case Msg.Kind is
               when AHT.Websocket.Text_Message =>
                  AHT.Websocket.Client.Send_Text (C, Msg.Payload.To_String);
               when AHT.Websocket.Binary_Message =>
                  AHT.Websocket.Client.Send_Binary (C, Msg.Payload.To_Array);
            end case;
         exception
            when others => exit Echo;
         end;
      end loop Echo;

      --  Always Close: joins the receiver task even when the loop ended
      --  on a timeout with the connection still nominally open.
      AHT.Websocket.Client.Close (C);
   end Run_Case;

   procedure Update_Reports is
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Connect
        (C, Base_URL & "/updateReports?agent=" & Agent);
      begin
         --  Server generates the reports then closes; just wait it out.
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 120.0);
      exception
         when others => null;
      end;
      AHT.Websocket.Client.Close (C);
   end Update_Reports;

   Count : Natural;

begin
   Put_Line ("autobahn: server=" & Base_URL & " agent=" & Agent);

   begin
      Count := Get_Case_Count;
   exception
      when E : others =>
         Put_Line ("autobahn: getCaseCount failed: "
                   & Ada.Exceptions.Exception_Name (E)
                   & " — is the fuzzingserver running at "
                   & Base_URL & "?");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
   end;

   if Count = 0 then
      Put_Line ("autobahn: case count is 0 — is the fuzzingserver running "
                & "at " & Base_URL & "?");
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;

   Put_Line ("autobahn: running " & Img (Count) & " cases");
   for I in 1 .. Count loop
      Run_Case (I);
      if I mod 25 = 0 or else I = Count then
         Put_Line ("  .. " & Img (I) & "/" & Img (Count));
         Flush;
      end if;
   end loop;

   Update_Reports;
   Put_Line ("autobahn: done — reports written to the server's outdir "
             & "(tests/autobahn/reports/index.json)");
end AHT_Autobahn;
