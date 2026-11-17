--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO;           use Ada.Text_IO;

with AHT.URL;

procedure Test_URL is

   use type AHT.URL.Scheme_Kind;

   Failures : Natural := 0;

   procedure Check (OK : Boolean; Message : String) is
   begin
      if not OK then
         Put_Line ("FAIL: " & Message);
         Failures := Failures + 1;
      end if;
   end Check;

   procedure Case_Basic_HTTP is
      U : constant AHT.URL.URL_Type :=
        AHT.URL.Parse ("http://example.com/path?x=1");
   begin
      Check (U.Scheme = AHT.URL.HTTP, "scheme http");
      Check (To_String (U.Host) = "example.com", "host");
      Check (U.Port = 80, "default port http");
      Check (To_String (U.Path) = "/path", "path");
      Check (To_String (U.Query) = "x=1", "query");
      Check (AHT.URL.Request_Target (U) = "/path?x=1", "request target");
   end Case_Basic_HTTP;

   procedure Case_HTTPS_Custom_Port is
      U : constant AHT.URL.URL_Type :=
        AHT.URL.Parse ("https://example.com:8443/");
   begin
      Check (U.Scheme = AHT.URL.HTTPS, "scheme https");
      Check (U.Port = 8443, "custom port");
      Check (AHT.URL.Is_Secure (U.Scheme), "is_secure");
   end Case_HTTPS_Custom_Port;

   procedure Case_WS_No_Path is
      U : constant AHT.URL.URL_Type :=
        AHT.URL.Parse ("ws://127.0.0.1:8765");
   begin
      Check (U.Scheme = AHT.URL.WS, "scheme ws");
      Check (To_String (U.Host) = "127.0.0.1", "host");
      Check (U.Port = 8765, "port");
      Check (To_String (U.Path) = "/", "default path");
      Check (AHT.URL.Request_Target (U) = "/", "request target /");
   end Case_WS_No_Path;

   procedure Case_Round_Trip is
      Input : constant String := "wss://host.example:443/chat?room=main";
      U     : constant AHT.URL.URL_Type := AHT.URL.Parse (Input);
   begin
      --  Port 443 is default for wss, so To_String should omit it.
      Check (AHT.URL.To_String (U) = "wss://host.example/chat?room=main",
             "round trip omits default port: got " & AHT.URL.To_String (U));
   end Case_Round_Trip;

   procedure Case_IPv6 is
      U : constant AHT.URL.URL_Type :=
        AHT.URL.Parse ("http://[::1]:8080/v1/health");
   begin
      Check (U.Is_IPv6, "IPv6 flag set");
      Check (To_String (U.Host) = "::1", "IPv6 host without brackets");
      Check (U.Port = 8080, "IPv6 port parsed");
      Check (AHT.URL.Host_Literal (U) = "[::1]", "host literal rebuilds brackets");
      Check (To_String (U.Path) = "/v1/health", "IPv6 path");
   end Case_IPv6;

   procedure Case_IPv6_Default_Port is
      U : constant AHT.URL.URL_Type :=
        AHT.URL.Parse ("https://[2001:db8::1]/");
   begin
      Check (U.Is_IPv6, "IPv6 flag");
      Check (To_String (U.Host) = "2001:db8::1", "IPv6 host");
      Check (U.Port = 443, "default https port");
   end Case_IPv6_Default_Port;

   procedure Case_UserInfo is
      U : constant AHT.URL.URL_Type :=
        AHT.URL.Parse ("http://alice:secret@example.com:8080/x");
   begin
      Check (To_String (U.User_Info) = "alice:secret", "userinfo");
      Check (To_String (U.Host) = "example.com", "host after @");
      Check (U.Port = 8080, "port after @");
   end Case_UserInfo;

   procedure Case_Invalid is
   begin
      if AHT.URL.Request_Target (AHT.URL.Parse ("gopher://x/"))'Length > 0 then
         Check (False, "should have raised on unsupported scheme");
      end if;
   exception
      when AHT.URL.Parse_Error =>
         null;
   end Case_Invalid;

   --  RFC 3986 sec. 5.4: every normal and abnormal example whose
   --  result is an http URL (5.4.1 "g:h" names another scheme).
   procedure Case_Resolve_RFC_Examples is
      Base : constant AHT.URL.URL_Type :=
        AHT.URL.Parse ("http://a/b/c/d;p?q");

      procedure Expect (Ref, Want : String) is
      begin
         declare
            Got : constant String :=
              AHT.URL.To_String (AHT.URL.Resolve (Base, Ref));
         begin
            Check (Got = Want,
                   "resolve """ & Ref & """ = " & Got & ", want " & Want);
         end;
      exception
         when E : others =>
            Check (False, "resolve """ & Ref & """ raised "
                   & Ada.Exceptions.Exception_Name (E));
      end Expect;
   begin
      Expect ("g",             "http://a/b/c/g");
      Expect ("./g",           "http://a/b/c/g");
      Expect ("g/",            "http://a/b/c/g/");
      Expect ("/g",            "http://a/g");
      Expect ("//g",           "http://g/");
      Expect ("?y",            "http://a/b/c/d;p?y");
      Expect ("g?y",           "http://a/b/c/g?y");
      Expect ("#s",            "http://a/b/c/d;p?q#s");
      Expect ("g#s",           "http://a/b/c/g#s");
      Expect ("g?y#s",         "http://a/b/c/g?y#s");
      Expect (";x",            "http://a/b/c/;x");
      Expect ("g;x",           "http://a/b/c/g;x");
      Expect ("g;x?y#s",       "http://a/b/c/g;x?y#s");
      Expect ("",              "http://a/b/c/d;p?q");
      Expect (".",             "http://a/b/c/");
      Expect ("./",            "http://a/b/c/");
      Expect ("..",            "http://a/b/");
      Expect ("../",           "http://a/b/");
      Expect ("../g",          "http://a/b/g");
      Expect ("../..",         "http://a/");
      Expect ("../../",        "http://a/");
      Expect ("../../g",       "http://a/g");
      Expect ("../../../g",    "http://a/g");
      Expect ("../../../../g", "http://a/g");
      Expect ("/./g",          "http://a/g");
      Expect ("/../g",         "http://a/g");
      Expect ("g.",            "http://a/b/c/g.");
      Expect (".g",            "http://a/b/c/.g");
      Expect ("g..",           "http://a/b/c/g..");
      Expect ("..g",           "http://a/b/c/..g");
      Expect ("./../g",        "http://a/b/g");
      Expect ("./g/.",         "http://a/b/c/g/");
      Expect ("g/./h",         "http://a/b/c/g/h");
      Expect ("g/../h",        "http://a/b/c/h");
      Expect ("g;x=1/./y",     "http://a/b/c/g;x=1/y");
      Expect ("g;x=1/../y",    "http://a/b/c/y");
      Expect ("g?y/./x",       "http://a/b/c/g?y/./x");
      Expect ("g?y/../x",      "http://a/b/c/g?y/../x");
      Expect ("g#s/./x",       "http://a/b/c/g#s/./x");
      Expect ("g#s/../x",      "http://a/b/c/g#s/../x");
   end Case_Resolve_RFC_Examples;

   procedure Case_Resolve_Other is
      Base : constant AHT.URL.URL_Type :=
        AHT.URL.Parse ("https://[::1]:8443/dir/page?x=1#top");
      R    : AHT.URL.URL_Type;
   begin
      --  Absolute: nothing of Base survives, dot segments still go.
      R := AHT.URL.Resolve (Base, "HTTP://Other.example:81/a/./b/../c");
      Check (R.Scheme = AHT.URL.HTTP, "absolute: scheme");
      Check (To_String (R.Host) = "Other.example", "absolute: host");
      Check (R.Port = 81, "absolute: port");
      Check (To_String (R.Path) = "/a/c", "absolute: path");

      --  Scheme-relative keeps Base's scheme only.
      R := AHT.URL.Resolve (Base, "//cdn.example/x");
      Check (R.Scheme = AHT.URL.HTTPS and then R.Port = 443
             and then To_String (R.Host) = "cdn.example",
             "scheme-relative: " & AHT.URL.To_String (R));

      --  Relative: Base's IPv6 authority, Base's fragment dropped.
      R := AHT.URL.Resolve (Base, "next");
      Check (AHT.URL.To_String (R) = "https://[::1]:8443/dir/next",
             "relative on IPv6 base: " & AHT.URL.To_String (R));

      --  Unsafe bytes are escaped, existing escapes kept.
      R := AHT.URL.Resolve (Base, "/a b/" & Character'Val (16#C3#)
                            & Character'Val (16#BC#) & "%41?q=<1>");
      Check (AHT.URL.Request_Target (R) = "/a%20b/%C3%BC%41?q=%3C1%3E",
             "escaping: " & AHT.URL.Request_Target (R));

      --  An unsafe byte in the host is refused, not escaped.
      begin
         R := AHT.URL.Resolve
           (Base, "http://b" & Character'Val (16#C3#)
                  & Character'Val (16#BC#) & "cher.example/");
         Check (False, "non-ASCII host did not raise");
      exception
         when AHT.URL.Parse_Error => null;
      end;

      --  A scheme without "//" is not something this client can follow.
      begin
         R := AHT.URL.Resolve (Base, "mailto:someone@example.com");
         Check (False, "mailto: did not raise");
      exception
         when AHT.URL.Parse_Error => null;
      end;
   end Case_Resolve_Other;

begin
   Case_Resolve_RFC_Examples;
   Case_Resolve_Other;
   Case_Basic_HTTP;
   Case_HTTPS_Custom_Port;
   Case_WS_No_Path;
   Case_Round_Trip;
   Case_IPv6;
   Case_IPv6_Default_Port;
   Case_UserInfo;
   Case_Invalid;

   if Failures = 0 then
      Put_Line ("test_url: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_url: " & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_URL;
