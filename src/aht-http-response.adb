--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Characters.Handling;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with AHT.HTTP.IO;

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
      Reason : out Unbounded_String)
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

   --  Streaming Content-Length body: read up to Chunk_Size bytes at
   --  a time, dispatch each fill to Sink. Single Read_N for small
   --  N (one chunk to Sink); larger N gets sliced into Chunk_Size
   --  pieces so users see progress on large downloads.
   procedure Read_N_Streaming
     (T      : in out AHT.Transport.Transport_Type'Class;
      N      : Natural;
      Sink   : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array))
   is
      Chunk_Size : constant Positive := 4_096;
      Remaining  : Natural := N;
   begin
      while Remaining > 0 loop
         declare
            This : constant Positive :=
              (if Remaining < Chunk_Size then Remaining else Chunk_Size);
            Buf  : AHT.Bytes.Byte_Array (1 .. This);
         begin
            AHT.HTTP.IO.Read_N (T, Buf);
            Sink (Buf);
            Remaining := Remaining - This;
         end;
      end loop;
   end Read_N_Streaming;

   --  Streaming read-until-EOF: pull whatever the transport gives
   --  us per Read and dispatch each slice to Sink until a 0-byte
   --  read signals peer close.
   procedure Read_Until_EOF_Streaming
     (T    : in out AHT.Transport.Transport_Type'Class;
      Sink : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array))
   is
      Buf  : AHT.Bytes.Byte_Array (1 .. 4_096);
      Last : Natural;
   begin
      loop
         T.Read (Buf, Last);
         exit when Last = 0;
         Sink (Buf (Buf'First .. Last));
      end loop;
   end Read_Until_EOF_Streaming;

   --  Common head parser used by Read and Read_Streaming: status
   --  line, headers, no-body suppression. Returns True if the body
   --  must be skipped (HEAD / 1xx / 204 / 205 / 304); False if the
   --  caller should proceed to body framing.
   procedure Parse_Head
     (Self        : out Response_Type;
      T           : in out AHT.Transport.Transport_Type'Class;
      Method      : AHT.HTTP.Methods.Method_Type;
      Skip_Body   : out Boolean)
   is
      use type AHT.HTTP.Methods.Method_Type;
   begin
      --  Start from a default state so repeated Reads can't leak
      --  residue from a prior response.
      Self := (others => <>);

      declare
         Status_Line : constant String := AHT.HTTP.IO.Read_Line (T);
      begin
         Parse_Status_Line (Status_Line, Self.Status, Self.Reason);
      end;

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

   procedure Read_Streaming
     (Self   : out Response_Type;
      T      : in out AHT.Transport.Transport_Type'Class;
      Sink   : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Method : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET)
   is
      Skip : Boolean;
   begin
      Parse_Head (Self, T, Method, Skip);
      if Skip then
         return;
      end if;

      --  Body framing: chunked wins, then Content-Length, then EOF.
      if Self.Headers.Contains ("transfer-encoding") then
         declare
            TE : constant String :=
              To_Lower (Self.Headers.Get ("transfer-encoding"));
         begin
            --  Only "chunked" is supported in v1. Anything else (gzip,
            --  deflate, chunked+gzip, ...) would need a codec stack we
            --  don't have yet, so refuse cleanly rather than silently
            --  hand back corrupted bytes.
            if TE = "chunked" then
               AHT.HTTP.IO.Read_Chunked_Body (T, Sink);
            else
               raise Protocol_Error with
                 "HTTP.Response: unsupported Transfer-Encoding: """
                 & TE & """";
            end if;
         end;
      elsif Self.Headers.Contains ("content-length") then
         declare
            N : constant Natural :=
              Parse_Content_Length
                (Strip_OWS (Self.Headers.Get ("content-length")));
         begin
            Read_N_Streaming (T, N, Sink);
         end;
      else
         Read_Until_EOF_Streaming (T, Sink);
      end if;
   end Read_Streaming;

   function Body_Text (Self : Response_Type) return String is
     (AHT.Bytes.To_String (Self.Body_B));

   procedure Read
     (Self   : out Response_Type;
      T      : in out AHT.Transport.Transport_Type'Class;
      Method : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET)
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
      Read_Streaming (Self, T, Append_To_Body'Access, Method);
   end Read;

end AHT.HTTP.Response;
