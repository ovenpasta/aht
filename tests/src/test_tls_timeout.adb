--  TLS handshake-timeout test. Drives both the transport-level
--  Handshake_Deadline and the HTTP client's Timeout_Seconds wiring
--  against tests/server/server_stall.py (127.0.0.1:8767), which
--  accepts the TCP connection but never sends a ServerHello. Without a
--  bounded handshake the client would block forever; with one it must
--  raise Timeout_Error promptly.
--
--  Run from the repo root (run_tests.sh chdir's there). The stall
--  server must be up — if it isn't, Connect fails on the TCP connect
--  with Transport_Error and the cases report that instead.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.HTTP.Client;
with AHT.HTTP.Response;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Timeout is

   Host     : constant String := "localhost";
   Port     : constant AHT.URL.Port_Number := 8767;
   Deadline : constant Duration := 1.0;
   --  Generous upper bound: the deadline is 1 s, so anything past this
   --  means the budget was ignored and the read effectively hung.
   Max_Wait : constant Duration := 8.0;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_timeout: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

begin
   --  Case 1: transport level. Insecure isolates this from cert
   --  verification — the server never presents a cert anyway, so the
   --  only way out is the handshake deadline.
   declare
      T       : AHT.Transport.TLS.TLS_Transport;
      Started : constant Time := Clock;
   begin
      begin
         T.Connect (Host, Port, Insecure => True,
                    Handshake_Deadline => Deadline);
         Fail ("transport: Connect returned without timing out");
      exception
         when AHT.Transport.Timeout_Error =>
            declare
               Elapsed : constant Duration := To_Duration (Clock - Started);
            begin
               if Elapsed > Max_Wait then
                  Fail ("transport: timed out but took"
                        & Elapsed'Image & "s (>" & Max_Wait'Image & "s)");
               end if;
            end;
         when E : others =>
            Fail ("transport: expected Timeout_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server_stall.py running?)");
      end;
      begin
         T.Close;
      exception
         when others => null;
      end;
   end;

   --  Case 2: HTTP client wiring. Client.Timeout_Seconds must flow
   --  through to Connect's Handshake_Deadline, so a Get against the
   --  stall server raises Timeout_Error instead of hanging.
   declare
      C       : AHT.HTTP.Client.Client_Type;
      Resp    : AHT.HTTP.Response.Response_Type;
      Started : constant Time := Clock;
   begin
      C.Insecure := True;
      C.Timeout_Seconds := 1;
      begin
         Resp := AHT.HTTP.Client.Get (C, "https://localhost:8767/hello");
         Fail ("client: Get returned status" & Resp.Status'Image
               & " without timing out");
      exception
         when AHT.Transport.Timeout_Error =>
            declare
               Elapsed : constant Duration := To_Duration (Clock - Started);
            begin
               if Elapsed > Max_Wait then
                  Fail ("client: timed out but took"
                        & Elapsed'Image & "s (>" & Max_Wait'Image & "s)");
               end if;
            end;
         when E : others =>
            Fail ("client: expected Timeout_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_timeout: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_timeout:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Timeout;
