--  HTTP client over https://. Exercises the scheme dispatch added in
--  split C2: AHT.HTTP.Client.Send now routes https:// through
--  AHT.Transport.TLS, threading Client_Type.CA_Path / .Insecure into
--  the handshake. The wire mechanics (header merge, body framing, 1xx
--  loop) are already covered by the plain-HTTP tests; this test's job
--  is to prove the TLS branch connects, verifies, and round-trips a
--  real response.
--
--  Talks to tests/server/server_tls.py on 127.0.0.1:8766, the same
--  fixture and self-signed cert that test_tls.adb uses. URLs name
--  "localhost" (not the IP) so SNI matches the cert's DNS:localhost
--  SAN under verification. Run from the repo root (run_tests.sh
--  chdir's there) so the relative CA path resolves.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Response;
with AHT.Transport.TLS;

procedure Test_HTTP_TLS is

   URL     : constant String := "https://localhost:8766/hello";
   CA_File : constant String := "tests/server/certs/server.crt";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_tls: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Body_To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

begin
   --  Case 1: verify against the fixture's own CA. The client must
   --  thread CA_Path into the handshake, verify the chain, and
   --  round-trip /hello.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      C.CA_Path :=
        Ada.Strings.Unbounded.To_Unbounded_String (CA_File);
      begin
         Resp := AHT.HTTP.Client.Get (C, URL);
         if Resp.Status /= 200 then
            Fail ("verify: status =" & Resp.Status'Image);
         elsif Body_To_String (Resp.Body_B) /= "hello, world" & ASCII.LF
         then
            Fail ("verify: body = """
                  & Body_To_String (Resp.Body_B) & """");
         end if;
      exception
         when E : others =>
            Fail ("verify: unexpected "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server_tls.py running?)");
      end;
   end;

   --  Case 2: Insecure bypasses verification — no CA supplied, the
   --  self-signed cert is accepted and /hello still round-trips.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      C.Insecure := True;
      begin
         Resp := AHT.HTTP.Client.Get (C, URL);
         if Resp.Status /= 200 then
            Fail ("insecure: status =" & Resp.Status'Image);
         elsif Body_To_String (Resp.Body_B) /= "hello, world" & ASCII.LF
         then
            Fail ("insecure: body = """
                  & Body_To_String (Resp.Body_B) & """");
         end if;
      exception
         when E : others =>
            Fail ("insecure: unexpected "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
   end;

   --  Case 3: verify required, no CA configured. The self-signed cert
   --  chains to no trusted root, so the handshake must be rejected with
   --  TLS_Error propagated up through the client rather than connecting.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := AHT.HTTP.Client.Get (C, URL);
      Fail ("untrusted: Get returned status" & Resp.Status'Image
            & " (expected TLS_Error)");
   exception
      when AHT.Transport.TLS.TLS_Error =>
         null;  --  expected: untrusted chain rejected
      when E : others =>
         Fail ("untrusted: expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;


   --  Case 4: the same anchor as PEM data on the client record.
   --
   --  Client_Type.CA_PEM is one forwarding line into the TLS connect,
   --  and a broken one would leave every other test in this suite
   --  green -- CA_Path would still work and nothing else reads the
   --  field. This is the only thing that would notice.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;

      function Read_File (Path : String) return String is
         F : File_Type;
         R : Ada.Strings.Unbounded.Unbounded_String;
      begin
         Open (F, In_File, Path);
         while not End_Of_File (F) loop
            Ada.Strings.Unbounded.Append (R, Get_Line (F));
            Ada.Strings.Unbounded.Append (R, ASCII.LF);
         end loop;
         Close (F);
         return Ada.Strings.Unbounded.To_String (R);
      exception
         when others =>
            if Is_Open (F) then
               Close (F);
            end if;
            return "";
      end Read_File;

      Cert : constant String := Read_File (CA_File);
   begin
      if Cert = "" then
         Fail ("ca-pem: could not read " & CA_File);
      else
         C.CA_PEM := Ada.Strings.Unbounded.To_Unbounded_String (Cert);
         begin
            Resp := AHT.HTTP.Client.Get (C, URL);
            if Resp.Status /= 200 then
               Fail ("ca-pem: status =" & Resp.Status'Image);
            elsif Body_To_String (Resp.Body_B) /= "hello, world" & ASCII.LF
            then
               Fail ("ca-pem: body = """
                     & Body_To_String (Resp.Body_B) & """");
            end if;
         exception
            when E : others =>
               Fail ("ca-pem: request raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E)
                     & " — Client_Type.CA_PEM is not reaching the "
                     & "handshake");
         end;

         --  Case 5: both fields set on the record. Refused when the
         --  HTTPS request consumes them -- they are persistent
         --  configuration, so the error belongs to the request that
         --  uses them, not to setting them.
         C.CA_Path :=
           Ada.Strings.Unbounded.To_Unbounded_String (CA_File);
         begin
            Resp := AHT.HTTP.Client.Get (C, URL);
            Fail ("ca-both: CA_Path and CA_PEM together were accepted");
         exception
            when AHT.Transport.TLS.TLS_Error =>
               null;   --  correct
            when E : others =>
               Fail ("ca-both: expected TLS_Error, got "
                     & Ada.Exceptions.Exception_Name (E));
         end;
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_http_tls: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_tls:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_TLS;
