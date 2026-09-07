--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Strings.Unbounded;

package AHT.URL is

   pragma Preelaborate;

   subtype Port_Number is Positive range 1 .. 65_535;

   type Scheme_Kind is (HTTP, HTTPS, WS, WSS);

   function Default_Port (S : Scheme_Kind) return Port_Number is
     (case S is
        when HTTP  => 80,
        when HTTPS => 443,
        when WS    => 80,
        when WSS   => 443);

   function Is_Secure (S : Scheme_Kind) return Boolean is
     (S = HTTPS or S = WSS);

   type URL_Type is record
      Scheme    : Scheme_Kind := HTTP;
      User_Info : Ada.Strings.Unbounded.Unbounded_String;
      --  Whatever sat between "scheme://" and "@", if any. Parsed so it
      --  doesn't corrupt Host; callers decide whether to translate it
      --  into an Authorization header (it is NOT auto-injected).
      Host      : Ada.Strings.Unbounded.Unbounded_String;
      --  For IPv6 literals the surrounding brackets are stripped, so
      --  "[::1]" is stored as "::1". Use Host_Literal to rebuild the
      --  request-line form.
      Is_IPv6   : Boolean := False;
      Port      : Port_Number := 80;
      Path      : Ada.Strings.Unbounded.Unbounded_String;
      Query     : Ada.Strings.Unbounded.Unbounded_String;
      Fragment  : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   Parse_Error : exception;

   function Parse (Input : String) return URL_Type
     with Post => Ada.Strings.Unbounded.Length (Parse'Result.Host) > 0;

   function To_String (U : URL_Type) return String;

   function Host_Literal (U : URL_Type) return String;
   --  Host as it appears in a URL: "example.com", "127.0.0.1", or
   --  "[::1]" for IPv6.

   function Request_Target (U : URL_Type) return String;
   --  The "path?query" that goes on the HTTP request line.

end AHT.URL;
