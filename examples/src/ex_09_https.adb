--  Example 9 — the same one-line GET, but over TLS (https://).
--
--  Nothing about the request changes from ex_01: Client.Get parses the
--  URL, sees the https:// scheme, and runs the round trip over an
--  AHT.Transport.TLS connection instead of plain TCP. The only
--  difference is trust configuration, and unlike the WebSocket client
--  (where it is a Connect parameter, see ex_08) the HTTP client carries
--  it as two fields on the Client_Type:
--    * Insecure => True accepts any certificate without verification.
--      We use it here because the bundled fixture serves a self-signed
--      cert with no CA to chain to. It is the WRONG default for real
--      traffic -- it disables the protection TLS exists to provide.
--    * In production leave Insecure False (the secure default) and set
--      CA_Path to your trust anchor instead, e.g.
--         Client.CA_Path := To_Unbounded_String ("/etc/ssl/certs/ca.pem");
--      Then the handshake verifies the peer cert against that CA.
--
--  Run:  ./examples/bin/<mode>/ex_09_https [URL]
--  Default URL is the bundled TLS fixture's /hello route on :8766; pass
--  any https:// URL to retarget. A public https:// host whose cert
--  chains to a system CA works with Insecure left False.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.HTTP.Client;
with AHT.HTTP.Response;

procedure Ex_09_HTTPS is

   Default_URL : constant String := "https://127.0.0.1:8766/hello";

   URL  : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_URL);

   Client : AHT.HTTP.Client.Client_Type;
   Resp   : AHT.HTTP.Response.Response_Type;
begin
   Put_Line ("GET " & URL & " (TLS, accepting self-signed cert)");

   --  Trust the fixture's self-signed cert. See the header comment: in
   --  production set Client.CA_Path instead and leave this False.
   Client.Insecure := True;

   Resp := AHT.HTTP.Client.Get (Client, URL);

   Put_Line ("  status : " & Resp.Status'Image);
   Put_Line ("  body   : " & Resp.Body_Text);
   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("request failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the TLS fixture up + cert generated? "
                & "try: bash examples/run_examples.sh)");
      Set_Exit_Status (Failure);
end Ex_09_HTTPS;
