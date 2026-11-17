--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Example 10: the three opt-in client behaviours, each one field on
--  Client_Type and each off until set.
--
--    Max_Redirects      follow a 302 and report where it ended
--                       (Resp.Final_URL).
--    Max_Decoded_Bytes  ask for and decode a gzip body. The field is
--                       the switch and the bound at once: a body that
--                       would decode past it raises Protocol_Error.
--    Pool               keep-alive. Two requests share one connection;
--                       the keep-alive fixture names the connection
--                       (X-Conn) and the request's place on it (X-Req)
--                       in every response, so the reuse is visible.
--
--  Run:  ./examples/bin/<mode>/ex_10_client_options [HOST [KEEPALIVE_HOST]]
--  HOST defaults to the HTTP fixture, http://127.0.0.1:8764, and
--  KEEPALIVE_HOST to the keep-alive fixture, http://127.0.0.1:8779
--  (the plain HTTP fixture closes every connection).

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.HTTP.Client;
with AHT.HTTP.Connection_Pools;
with AHT.HTTP.Response;
with AHT.URL;

procedure Ex_10_Client_Options is

   Host : constant String :=
     (if Argument_Count >= 1 then Argument (1) else "http://127.0.0.1:8764");

   Keepalive_Host : constant String :=
     (if Argument_Count >= 2 then Argument (2) else "http://127.0.0.1:8779");

   Resp : AHT.HTTP.Response.Response_Type;
begin
   --  Redirects. Without Max_Redirects the 302 itself comes back.
   declare
      Client : AHT.HTTP.Client.Client_Type;
      URL    : constant String := Host & "/redirect";
   begin
      Put_Line ("GET " & URL);
      Resp := AHT.HTTP.Client.Get (Client, URL);
      Put_Line ("  default         : status" & Resp.Status'Image
                & ", Location " & Resp.Headers.Get ("location"));

      Client.Max_Redirects := 5;
      Resp := AHT.HTTP.Client.Get (Client, URL);
      Put_Line ("  Max_Redirects 5 : status" & Resp.Status'Image
                & ", ended at " & AHT.URL.To_String (Resp.Final_URL));
   end;

   --  Content decoding. Without a bound the gzip bytes come back as
   --  sent; with one, the client sends Accept-Encoding and decodes.
   New_Line;
   declare
      Client : AHT.HTTP.Client.Client_Type;
      URL    : constant String := Host & "/coded/gzip-text";
   begin
      Put_Line ("GET " & URL);
      Resp := AHT.HTTP.Client.Get (Client, URL);
      Put_Line ("  default           :" & Resp.Body_B.Length'Image
                & " bytes, Content-Encoding "
                & Resp.Headers.Get ("content-encoding"));

      Client.Max_Decoded_Bytes := 1_048_576;   --  1 MiB
      Resp := AHT.HTTP.Client.Get (Client, URL);
      Put_Line ("  Max_Decoded 1 MiB :" & Resp.Body_B.Length'Image
                & " bytes, Decoded " & Resp.Decoded'Image);
   end;

   --  Keep-alive. The pool is a shared handle: copies of the client
   --  use the same one, and the last copy closes what is idle.
   New_Line;
   declare
      Client : AHT.HTTP.Client.Client_Type;
      URL    : constant String := Keepalive_Host & "/ka/hello";
   begin
      Client.Pool := AHT.HTTP.Connection_Pools.Create;
      Put_Line ("GET " & URL & " (twice, one Pool)");
      for I in 1 .. 2 loop
         Resp := AHT.HTTP.Client.Get (Client, URL);
         Put_Line ("  request" & I'Image
                   & " : connection " & Resp.Headers.Get ("x-conn")
                   & ", request " & Resp.Headers.Get ("x-req") & " on it");
      end loop;
      Put_Line ("  idle in pool :"
                & AHT.HTTP.Connection_Pools.Idle_Count (Client.Pool)'Image);
   end;

   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("request failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(are the fixtures up? try: bash examples/run_examples.sh)");
      Set_Exit_Status (Failure);
end Ex_10_Client_Options;
