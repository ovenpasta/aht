with Ada.Characters.Handling;
with Ada.Strings.Fixed;

package body AHT.URL is

   use Ada.Strings.Unbounded;

   function Parse_Scheme (S : String; After : out Positive) return Scheme_Kind;
   --  On success, sets After to the index of the first char past "://".

   function Parse_Scheme (S : String; After : out Positive) return Scheme_Kind is
      Colon_Slash_Slash : constant String := "://";
      Idx : constant Natural :=
        Ada.Strings.Fixed.Index (S, Colon_Slash_Slash);
   begin
      if Idx = 0 then
         raise Parse_Error with "URL missing scheme://";
      end if;

      declare
         Lower : constant String :=
           Ada.Characters.Handling.To_Lower (S (S'First .. Idx - 1));
      begin
         After := Idx + Colon_Slash_Slash'Length;
         if Lower = "http" then
            return HTTP;
         elsif Lower = "https" then
            return HTTPS;
         elsif Lower = "ws" then
            return WS;
         elsif Lower = "wss" then
            return WSS;
         else
            raise Parse_Error with "unsupported scheme: " & Lower;
         end if;
      end;
   end Parse_Scheme;

   procedure Parse_Port
     (S : String; Port : out Port_Number)
   is
      P : Integer;
   begin
      if S'Length = 0 then
         raise Parse_Error with "URL has empty port";
      end if;
      for C of S loop
         if C not in '0' .. '9' then
            raise Parse_Error with "URL port not numeric: " & S;
         end if;
      end loop;
      P := Integer'Value (S);
      if P not in Port_Number then
         raise Parse_Error with "URL port out of range: " & S;
      end if;
      Port := P;
   exception
      when Constraint_Error =>
         raise Parse_Error with "URL port not numeric: " & S;
   end Parse_Port;

   function Parse (Input : String) return URL_Type is
      After_Scheme : Positive;
      Result       : URL_Type;
      I            : Positive;
   begin
      Result.Scheme := Parse_Scheme (Input, After_Scheme);
      Result.Port := Default_Port (Result.Scheme);

      if After_Scheme > Input'Last then
         raise Parse_Error with "URL missing host";
      end if;

      --  Authority runs until '/', '?', '#', or end-of-input.
      I := After_Scheme;
      declare
         Auth_Start : constant Positive := I;
         Auth_End   : Positive;
         At_Sign    : Natural := 0;
         Host_Start : Positive;
         Host_End   : Natural;
      begin
         while I <= Input'Last loop
            exit when Input (I) = '/' or else Input (I) = '?'
                      or else Input (I) = '#';
            I := I + 1;
         end loop;
         Auth_End := I - 1;

         if Auth_End < Auth_Start then
            raise Parse_Error with "URL missing host";
         end if;

         --  Split off userinfo at the LAST '@' in the authority (any '@'
         --  inside userinfo must be percent-encoded per RFC 3986 §3.2.1).
         At_Sign :=
           Ada.Strings.Fixed.Index
             (Input (Auth_Start .. Auth_End), "@",
              Going => Ada.Strings.Backward);

         if At_Sign /= 0 then
            Result.User_Info :=
              To_Unbounded_String (Input (Auth_Start .. At_Sign - 1));
            Host_Start := At_Sign + 1;
         else
            Host_Start := Auth_Start;
         end if;

         if Host_Start > Auth_End then
            raise Parse_Error with "URL missing host";
         end if;

         --  IPv6 literal: "[...]" optionally followed by ":port".
         if Input (Host_Start) = '[' then
            declare
               Close : constant Natural :=
                 Ada.Strings.Fixed.Index
                   (Input (Host_Start .. Auth_End), "]");
            begin
               if Close = 0 then
                  raise Parse_Error with "IPv6 literal missing ']'";
               end if;
               Result.Is_IPv6 := True;
               Result.Host :=
                 To_Unbounded_String (Input (Host_Start + 1 .. Close - 1));
               Host_End := Close;

               if Host_End < Auth_End then
                  if Input (Host_End + 1) /= ':' then
                     raise Parse_Error with
                       "unexpected character after IPv6 literal";
                  end if;
                  Parse_Port
                    (Input (Host_End + 2 .. Auth_End), Result.Port);
               end if;
            end;

         else
            --  Regular host[:port] — split on the LAST ':' (hosts cannot
            --  contain ':' outside IPv6 brackets).
            declare
               Colon : constant Natural :=
                 Ada.Strings.Fixed.Index
                   (Input (Host_Start .. Auth_End), ":",
                    Going => Ada.Strings.Backward);
            begin
               if Colon = 0 then
                  Result.Host :=
                    To_Unbounded_String (Input (Host_Start .. Auth_End));
               else
                  Result.Host :=
                    To_Unbounded_String (Input (Host_Start .. Colon - 1));
                  Parse_Port
                    (Input (Colon + 1 .. Auth_End), Result.Port);
               end if;
            end;
         end if;
      end;

      if Length (Result.Host) = 0 then
         raise Parse_Error with "URL host is empty";
      end if;

      --  Path
      if I <= Input'Last and then Input (I) = '/' then
         declare
            Path_Start : constant Positive := I;
         begin
            while I <= Input'Last
              and then Input (I) /= '?' and then Input (I) /= '#'
            loop
               I := I + 1;
            end loop;
            Result.Path :=
              To_Unbounded_String (Input (Path_Start .. I - 1));
         end;
      else
         Result.Path := To_Unbounded_String ("/");
      end if;

      --  Query
      if I <= Input'Last and then Input (I) = '?' then
         declare
            Q_Start : constant Positive := I + 1;
         begin
            I := Q_Start;
            while I <= Input'Last and then Input (I) /= '#' loop
               I := I + 1;
            end loop;
            Result.Query := To_Unbounded_String (Input (Q_Start .. I - 1));
         end;
      end if;

      --  Fragment
      if I <= Input'Last and then Input (I) = '#' then
         Result.Fragment :=
           To_Unbounded_String (Input (I + 1 .. Input'Last));
      end if;

      return Result;
   end Parse;

   function Scheme_Image (S : Scheme_Kind) return String is
     (case S is
        when HTTP  => "http",
        when HTTPS => "https",
        when WS    => "ws",
        when WSS   => "wss");

   function Host_Literal (U : URL_Type) return String is
     (if U.Is_IPv6 then "[" & To_String (U.Host) & "]"
      else To_String (U.Host));

   function To_String (U : URL_Type) return String is
      Out_S : Unbounded_String;
   begin
      Append (Out_S, Scheme_Image (U.Scheme));
      Append (Out_S, "://");
      if Length (U.User_Info) > 0 then
         Append (Out_S, U.User_Info);
         Append (Out_S, "@");
      end if;
      Append (Out_S, Host_Literal (U));
      if U.Port /= Default_Port (U.Scheme) then
         Append (Out_S, ":");
         Append (Out_S, Ada.Strings.Fixed.Trim (U.Port'Image, Ada.Strings.Both));
      end if;
      if Length (U.Path) = 0 then
         Append (Out_S, "/");
      else
         Append (Out_S, U.Path);
      end if;
      if Length (U.Query) > 0 then
         Append (Out_S, "?");
         Append (Out_S, U.Query);
      end if;
      if Length (U.Fragment) > 0 then
         Append (Out_S, "#");
         Append (Out_S, U.Fragment);
      end if;
      return To_String (Out_S);
   end To_String;

   function Request_Target (U : URL_Type) return String is
      Path_S : constant String :=
        (if Length (U.Path) = 0 then "/" else To_String (U.Path));
   begin
      if Length (U.Query) > 0 then
         return Path_S & "?" & To_String (U.Query);
      else
         return Path_S;
      end if;
   end Request_Target;

end AHT.URL;
