--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Characters.Handling;
with Ada.Exceptions;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with AHT.HTTP.IO;
with AHT.Inflate;

package body AHT.HTTP.Response is

   --  Lowercase a String. Used to normalise header names before
   --  case-insensitive lookup.
   function To_Lower (S : String) return String is
     (Ada.Characters.Handling.To_Lower (S));

   --  Trim ASCII HT/SP off both ends of S. RFC 7230 sec. 3.2.4 calls
   --  this "OWS stripping". Not using Ada.Strings.Fixed.Trim because
   --  its Whitespace_Set default doesn't include HT in some runtimes;
   --  being explicit is cheap and unambiguous.
   function Strip_OWS (S : String) return String is
      First : Natural := S'First;
      Last  : Integer := S'Last;
   begin
      while First <= Last
        and then (S (First) = ' ' or else S (First) = ASCII.HT)
      loop
         First := First + 1;
      end loop;
      while Last >= First
        and then (S (Last) = ' ' or else S (Last) = ASCII.HT)
      loop
         Last := Last - 1;
      end loop;
      return S (First .. Last);
   end Strip_OWS;

   --  Parse a Content-Length value: ASCII digits, no sign, no
   --  whitespace inside, within Natural.
   function Parse_Content_Length (S : String) return Natural is
      Result : Natural := 0;
      Digit  : Natural;
   begin
      if S'Length = 0 then
         raise Protocol_Error with "HTTP.Response: empty Content-Length";
      end if;
      for C of S loop
         if C not in '0' .. '9' then
            raise Protocol_Error with
              "HTTP.Response: non-digit in Content-Length '" & C & "'";
         end if;
         Digit := Character'Pos (C) - Character'Pos ('0');
         if Result > (Natural'Last - Digit) / 10 then
            raise Protocol_Error with
              "HTTP.Response: Content-Length overflows Natural";
         end if;
         Result := Result * 10 + Digit;
      end loop;
      return Result;
   end Parse_Content_Length;

   --  Status line = "HTTP/1.1 {code} {reason}". Version must be
   --  HTTP/1.x because we don't speak 2 or 3. Reason is optional
   --  after the second SP.
   procedure Parse_Status_Line
     (Line   : String;
      Code   : out AHT.HTTP.Status.Status_Code;
      Reason : out Unbounded_String;
      Minor  : out Natural)
   is
      First_SP : Natural;
      Second_SP : Natural;
   begin
      First_SP := Ada.Strings.Fixed.Index (Line, " ");
      if First_SP = 0 then
         raise Protocol_Error with
           "HTTP.Response: status line missing first SP: """
           & Line & """";
      end if;

      declare
         Version : constant String := Line (Line'First .. First_SP - 1);
      begin
         if Version'Length < 8
           or else Version (Version'First .. Version'First + 4) /= "HTTP/"
           or else Version (Version'First + 5) /= '1'
           or else Version (Version'First + 6) /= '.'
           or else Version (Version'First + 7) not in '0' .. '9'
         then
            raise Protocol_Error with
              "HTTP.Response: unsupported version """ & Version & """";
         end if;
         Minor := Character'Pos (Version (Version'First + 7))
                  - Character'Pos ('0');
      end;

      Second_SP := Ada.Strings.Fixed.Index
        (Line (First_SP + 1 .. Line'Last), " ");

      declare
         Code_Str : constant String :=
           (if Second_SP = 0
            then Line (First_SP + 1 .. Line'Last)
            else Line (First_SP + 1 .. Second_SP - 1));
         Raw      : Integer;
      begin
         if Code_Str'Length /= 3 then
            raise Protocol_Error with
              "HTTP.Response: status code not 3 digits: """
              & Code_Str & """";
         end if;
         for C of Code_Str loop
            if C not in '0' .. '9' then
               raise Protocol_Error with
                 "HTTP.Response: non-digit in status code: """
                 & Code_Str & """";
            end if;
         end loop;
         Raw := Integer'Value (Code_Str);
         if Raw not in 100 .. 599 then
            raise Protocol_Error with
              "HTTP.Response: status out of range:"
              & Integer'Image (Raw);
         end if;
         Code := AHT.HTTP.Status.Status_Code (Raw);
      end;

      if Second_SP = 0 then
         Reason := Null_Unbounded_String;
      else
         Reason := To_Unbounded_String (Line (Second_SP + 1 .. Line'Last));
      end if;
   end Parse_Status_Line;

   --  Header line = "Name: value". Colon is mandatory. Name is
   --  stored lowercase by the Headers map; we pre-lowercase here
   --  so the Headers invariant holds unconditionally.
   procedure Parse_Header_Line
     (Line        : String;
      Out_Headers : in out AHT.HTTP.Headers.Map)
   is
      Colon : constant Natural := Ada.Strings.Fixed.Index (Line, ":");
   begin
      if Colon = 0 or else Colon = Line'First then
         raise Protocol_Error with
           "HTTP.Response: malformed header line: """ & Line & """";
      end if;
      Out_Headers.Append
        (Name  => To_Lower (Line (Line'First .. Colon - 1)),
         Value => Strip_OWS (Line (Colon + 1 .. Line'Last)));
   end Parse_Header_Line;

   --  Common head parser used by Read and Read_Streaming: status
   --  line, headers, no-body suppression. Returns True if the body
   --  must be skipped (HEAD / 1xx / 204 / 205 / 304); False if the
   --  caller should proceed to body framing.
   procedure Parse_Head
     (Self        : out Response_Type;
      T           : in out AHT.Transport.Transport_Type'Class;
      Method      : AHT.HTTP.Methods.Method_Type;
      Skip_Body   : out Boolean;
      Minor       : out Natural;
      Head_Read   : access Boolean)
   is
      use type AHT.HTTP.Methods.Method_Type;
   begin
      --  Start from a default state so repeated Reads can't leak
      --  residue from a prior response.
      Self := (others => <>);

      declare
         Status_Line : constant String := AHT.HTTP.IO.Read_Line (T);
      begin
         Parse_Status_Line
           (Status_Line, Self.Status, Self.Reason, Minor);
      end;
      if Head_Read /= null then
         Head_Read.all := True;
      end if;

      loop
         declare
            Line : constant String := AHT.HTTP.IO.Read_Line (T);
         begin
            exit when Line'Length = 0;
            Parse_Header_Line (Line, Self.Headers);
         end;
      end loop;

      --  RFC 7230 sec. 3.3.3 rule 1 and RFC 9110 sec. 15.3.6: HEAD,
      --  1xx, 204, 205 and 304 carry no body whatever the framing
      --  headers say; the message ends at the empty line. Reading on
      --  would block on a HEAD's advertised Content-Length, eat a
      --  101's upgraded-protocol bytes, or wait for EOF on a
      --  Connection: close 204.
      Skip_Body :=
        Method = AHT.HTTP.Methods.HEAD
        or else Self.Status in 100 .. 199
        or else Self.Status = 204
        or else Self.Status = 205
        or else Self.Status = 304;
   end Parse_Head;

   --  Body framing: chunked wins, then Content-Length, then EOF.
   --  Only "chunked" is understood as a Transfer-Encoding; any other
   --  (gzip, chunked+gzip, ...) is refused rather than handed back as
   --  undecoded bytes.
   procedure Select_Framing
     (Self      : Response_Type;
      Skip_Body : Boolean;
      Reader    : out AHT.HTTP.IO.Body_Reader)
   is
      use AHT.HTTP.IO;
   begin
      if Skip_Body then
         Start (Reader, No_Body);
      elsif Self.Headers.Contains ("transfer-encoding") then
         declare
            TE : constant String :=
              To_Lower (Self.Headers.Get ("transfer-encoding"));
         begin
            if TE /= "chunked" then
               raise Protocol_Error with
                 "HTTP.Response: unsupported Transfer-Encoding: """
                 & TE & """";
            end if;
            Start (Reader, Chunked);
         end;
      elsif Self.Headers.Contains ("content-length") then
         declare
            First : constant String :=
              Strip_OWS (Self.Headers.Get ("content-length"));
         begin
            --  RFC 9112 sec. 6.3: lengths that disagree leave the end
            --  of the message unknowable.
            for V of Self.Headers.Values ("content-length") loop
               if Strip_OWS (V) /= First then
                  raise Protocol_Error with
                    "HTTP.Response: conflicting Content-Length values """
                    & First & """ and """ & Strip_OWS (V) & """";
               end if;
            end loop;
            Start (Reader, Fixed, Parse_Content_Length (First));
         end;
      else
         Start (Reader, Until_Close);
      end if;
   end Select_Framing;

   --  The decoder for Self's single Content-Encoding, if it has one
   --  this package decodes.
   procedure Select_Coding
     (Self   : Response_Type;
      Coded  : out Boolean;
      Format : out AHT.Inflate.Format) is
   begin
      Coded  := False;
      Format := AHT.Inflate.Gzip;
      if Self.Status = 206
        or else Natural (Self.Headers.Values ("content-encoding").Length) /= 1
      then
         return;
      end if;
      declare
         CE : constant String :=
           To_Lower (Strip_OWS (Self.Headers.Get ("content-encoding")));
      begin
         if CE = "gzip" or else CE = "x-gzip" then
            Coded := True;
            Format := AHT.Inflate.Gzip;
         elsif CE = "deflate" then
            Coded := True;
            Format := AHT.Inflate.Zlib_Or_Raw;
         end if;
      end;
   end Select_Coding;

   --  True when a Connection header lists "close".
   function Lists_Close (Self : Response_Type) return Boolean is
   begin
      for V of Self.Headers.Values ("connection") loop
         declare
            Lower : constant String := To_Lower (V);
            First : Positive := Lower'First;
         begin
            while First <= Lower'Last + 1 loop
               declare
                  Comma : constant Natural :=
                    Ada.Strings.Fixed.Index
                      (Lower (First .. Lower'Last), ",");
                  Stop  : constant Natural :=
                    (if Comma = 0 then Lower'Last else Comma - 1);
               begin
                  if Strip_OWS (Lower (First .. Stop)) = "close" then
                     return True;
                  end if;
                  exit when Comma = 0;
                  First := Comma + 1;
               end;
            end loop;
         end;
      end loop;
      return False;
   end Lists_Close;

   procedure Read_Streaming
     (Self       : out Response_Type;
      T          : in out AHT.Transport.Transport_Type'Class;
      Sink       : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Method      : AHT.HTTP.Methods.Method_Type;
      Max_Decoded : Decode_Limit;
      Persistent  : out Boolean;
      Head_Read   : access Boolean := null)
   is
      use type Interfaces.Integer_64;

      Skip   : Boolean;
      Minor  : Natural;
      Reader : AHT.HTTP.IO.Body_Reader;
      Coded  : Boolean := False;
      Format : AHT.Inflate.Format;
      Framed : Boolean;

      Decoded_Total : Interfaces.Integer_64 := 0;

      procedure Pull (Data : out AHT.Bytes.Byte_Array; Last : out Natural) is
      begin
         AHT.HTTP.IO.Read (Reader, T, Data, Last);
      end Pull;

      --  The decoder's output, held to Max_Decoded.
      procedure Bounded_Sink (Chunk : AHT.Bytes.Byte_Array) is
         Room : constant Interfaces.Integer_64 :=
           Max_Decoded - Decoded_Total;
      begin
         if Interfaces.Integer_64 (Chunk'Length) > Room then
            if Room > 0 then
               Sink (Chunk (Chunk'First .. Chunk'First + Natural (Room) - 1));
               Decoded_Total := Max_Decoded;
            end if;
            raise Protocol_Error with
              "HTTP.Response: decoded body exceeds Max_Decoded ("
              & Ada.Strings.Fixed.Trim (Max_Decoded'Image, Ada.Strings.Both)
              & " bytes)";
         end if;
         Decoded_Total := Decoded_Total + Interfaces.Integer_64 (Chunk'Length);
         Sink (Chunk);
      end Bounded_Sink;
   begin
      Persistent := False;
      Parse_Head (Self, T, Method, Skip, Minor, Head_Read);
      Select_Framing (Self, Skip, Reader);
      --  Every framing but read-until-close ends at a known byte.
      Framed := Skip
        or else Self.Headers.Contains ("transfer-encoding")
        or else Self.Headers.Contains ("content-length");

      if Max_Decoded /= No_Decoding and then not Skip then
         Select_Coding (Self, Coded, Format);
      end if;

      if Coded then
         Self.Headers.Remove ("content-encoding");
         Self.Headers.Remove ("content-length");
         Self.Decoded := True;
         begin
            AHT.Inflate.Decode (Format, Pull'Access, Bounded_Sink'Access);
         exception
            when E : AHT.Inflate.Data_Error =>
               raise Protocol_Error with
                 "HTTP.Response: coded body: "
                 & Ada.Exceptions.Exception_Message (E);
         end;
      else
         declare
            Buf  : AHT.Bytes.Byte_Array (1 .. 4_096);
            Last : Natural;
         begin
            loop
               AHT.HTTP.IO.Read (Reader, T, Buf, Last);
               exit when Last < Buf'First;
               Sink (Buf (Buf'First .. Last));
            end loop;
         end;
      end if;

      Persistent := Framed
        and then AHT.HTTP.IO.At_End (Reader)
        and then Self.Status /= 101
        and then Minor >= 1
        and then not Lists_Close (Self)
        and then not
          (Self.Headers.Contains ("transfer-encoding")
           and then
             (Self.Headers.Contains ("content-length")
              or else Natural
                (Self.Headers.Values ("transfer-encoding").Length) > 1));
   end Read_Streaming;

   procedure Read_Streaming
     (Self   : out Response_Type;
      T      : in out AHT.Transport.Transport_Type'Class;
      Sink   : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Method      : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET;
      Max_Decoded : Decode_Limit := No_Decoding)
   is
      Ignore : Boolean;
   begin
      Read_Streaming (Self, T, Sink, Method, Max_Decoded, Ignore);
   end Read_Streaming;

   function Body_Text (Self : Response_Type) return String is
     (AHT.Bytes.To_String (Self.Body_B));

   procedure Read
     (Self   : out Response_Type;
      T      : in out AHT.Transport.Transport_Type'Class;
      Method      : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET;
      Max_Decoded : Decode_Limit := No_Decoding)
   is
      --  Body sink that appends every delivered chunk to Self.Body_B.
      --  Parse_Head (called inside Read_Streaming) clears Self before
      --  this sink ever sees a chunk, so the append-only sink builds
      --  up a fresh body.
      procedure Append_To_Body (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Self.Body_B.Append (Chunk);
      end Append_To_Body;
   begin
      Read_Streaming
        (Self, T, Append_To_Body'Access, Method, Max_Decoded);
   end Read;

end AHT.HTTP.Response;
