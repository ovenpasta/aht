--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

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
         --  inside userinfo must be percent-encoded, RFC 3986 3.2.1).
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
            --  Regular host[:port], split on the LAST ':' (hosts cannot
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

   ---------------------------------------------------------------------
   --  Reference resolution (RFC 3986 sec. 5.2)
   ---------------------------------------------------------------------

   --  Percent-encode the bytes a request target may not carry.
   function Escape_Unsafe (S : String) return String is
      Hex : constant String := "0123456789ABCDEF";
      R   : Unbounded_String;
   begin
      for C of S loop
         declare
            P : constant Natural := Character'Pos (C);
         begin
            if P <= 16#20# or else P >= 16#7F#
              or else C in '"' | '<' | '>' | '\' | '^' | '`'
                         | '{' | '|' | '}'
            then
               Append (R, '%');
               Append (R, Hex (P / 16 + 1));
               Append (R, Hex (P mod 16 + 1));
            else
               Append (R, C);
            end if;
         end;
      end loop;
      return To_String (R);
   end Escape_Unsafe;

   --  RFC 3986 sec. 5.2.4.
   function Remove_Dot_Segments (Path : String) return String is
      Input  : Unbounded_String := To_Unbounded_String (Path);
      Output : Unbounded_String;

      function Starts (Prefix : String) return Boolean is
        (Length (Input) >= Prefix'Length
         and then Slice (Input, 1, Prefix'Length) = Prefix);

      --  Drop the last segment of Output and its preceding "/".
      procedure Pop_Output is
         S : constant String := To_String (Output);
         Slash : constant Natural :=
           Ada.Strings.Fixed.Index (S, "/", Going => Ada.Strings.Backward);
      begin
         if Slash = 0 then
            Output := Null_Unbounded_String;
         else
            Output := To_Unbounded_String (S (S'First .. Slash - 1));
         end if;
      end Pop_Output;
   begin
      while Length (Input) > 0 loop
         if Starts ("../") then
            Delete (Input, 1, 3);
         elsif Starts ("./") then
            Delete (Input, 1, 2);
         elsif Starts ("/./") then
            Delete (Input, 1, 2);
         elsif To_String (Input) = "/." then
            Input := To_Unbounded_String ("/");
         elsif Starts ("/../") then
            Delete (Input, 1, 3);
            Pop_Output;
         elsif To_String (Input) = "/.." then
            Input := To_Unbounded_String ("/");
            Pop_Output;
         elsif To_String (Input) = "." or else To_String (Input) = ".." then
            Input := Null_Unbounded_String;
         else
            --  Move the first segment, with its leading "/" if any,
            --  to Output.
            declare
               S    : constant String := To_String (Input);
               Next : constant Natural :=
                 Ada.Strings.Fixed.Index (S (S'First + 1 .. S'Last), "/");
               Stop : constant Natural := (if Next = 0 then S'Last else Next - 1);
            begin
               Append (Output, S (S'First .. Stop));
               Input := To_Unbounded_String (S (Stop + 1 .. S'Last));
            end;
         end if;
      end loop;
      return To_String (Output);
   end Remove_Dot_Segments;

   function Has_Scheme (S : String) return Boolean is
   begin
      if S'Length = 0 or else S (S'First) not in 'a' .. 'z' | 'A' .. 'Z' then
         return False;
      end if;
      for I in S'First + 1 .. S'Last loop
         case S (I) is
            when ':' => return True;
            when 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '+' | '-' | '.' =>
               null;
            when others => return False;
         end case;
      end loop;
      return False;
   end Has_Scheme;

   function Resolve (Base : URL_Type; Reference : String) return URL_Type is
      Ref    : String renames Reference;
      Result : URL_Type;
   begin
      if Has_Scheme (Ref) then
         Result := Parse (Ref);
      elsif Ref'Length >= 2 and then Ref (Ref'First .. Ref'First + 1) = "//" then
         Result := Parse (Scheme_Image (Base.Scheme) & ":" & Ref);
      else
         --  Same authority as Base; split Ref into path ? query # frag.
         declare
            Hash  : constant Natural := Ada.Strings.Fixed.Index (Ref, "#");
            Head_Last : constant Natural :=
              (if Hash = 0 then Ref'Last else Hash - 1);
            Quest : constant Natural :=
              Ada.Strings.Fixed.Index (Ref (Ref'First .. Head_Last), "?");
            Path_Last : constant Natural :=
              (if Quest = 0 then Head_Last else Quest - 1);
            Path  : constant String := Ref (Ref'First .. Path_Last);
         begin
            Result := Base;
            Result.Fragment := Null_Unbounded_String;
            if Hash /= 0 then
               Result.Fragment :=
                 To_Unbounded_String (Ref (Hash + 1 .. Ref'Last));
            end if;

            if Path'Length = 0 then
               --  Path from Base; the query only if Ref has none.
               if Quest /= 0 then
                  Result.Query :=
                    To_Unbounded_String (Ref (Quest + 1 .. Head_Last));
               end if;
            else
               Result.Query := Null_Unbounded_String;
               if Quest /= 0 then
                  Result.Query :=
                    To_Unbounded_String (Ref (Quest + 1 .. Head_Last));
               end if;
               if Path (Path'First) = '/' then
                  Result.Path := To_Unbounded_String (Path);
               else
                  --  Merge (sec. 5.2.3): Base's path up to its last
                  --  "/", then Path.
                  declare
                     B     : constant String :=
                       (if Length (Base.Path) = 0 then "/"
                        else To_String (Base.Path));
                     Slash : constant Natural :=
                       Ada.Strings.Fixed.Index
                         (B, "/", Going => Ada.Strings.Backward);
                  begin
                     Result.Path :=
                       To_Unbounded_String (B (B'First .. Slash) & Path);
                  end;
               end if;
            end if;
         end;
      end if;

      --  Escaping is for the path and query only. A host cannot be
      --  repaired by it: an escaped host is a different, unresolvable
      --  name, so one with such bytes is refused.
      declare
         Host : constant String := To_String (Result.Host);
      begin
         if Escape_Unsafe (Host) /= Host then
            raise Parse_Error with "URL host has an invalid character";
         end if;
      end;

      declare
         Clean : constant String :=
           Remove_Dot_Segments (Escape_Unsafe (To_String (Result.Path)));
      begin
         Result.Path :=
           To_Unbounded_String (if Clean'Length = 0 then "/" else Clean);
         Result.Query :=
           To_Unbounded_String (Escape_Unsafe (To_String (Result.Query)));
      end;
      return Result;
   end Resolve;

end AHT.URL;
