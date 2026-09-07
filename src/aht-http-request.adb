--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with AHT.HTTP.IO;

package body AHT.HTTP.Request is

   use type Interfaces.Integer_64;

   CRLF : constant String := ASCII.CR & ASCII.LF;

   --  64 KiB pull window, matching the transport's write window so the
   --  encoder stays O(1) in body size.
   Window_Max : constant := 65_536;

   function Image_No_Space (N : Natural) return String is
     (Ada.Strings.Fixed.Trim (Natural'Image (N), Ada.Strings.Left));

   function Image_64 (N : Byte_Count) return String is
     (Ada.Strings.Fixed.Trim (Byte_Count'Image (N), Ada.Strings.Left));

   --  Strict decimal parse into Byte_Count: non-empty, ASCII digits only
   --  (no sign, no surrounding space), overflow past Byte_Count'Last
   --  raises Protocol_Error rather than wrapping.
   function Parse_Byte_Count (S : String) return Byte_Count is
      Result : Interfaces.Integer_64 := 0;
      D      : Interfaces.Integer_64;
   begin
      if S'Length = 0 then
         raise Protocol_Error with "HTTP.Request: empty Content-Length";
      end if;
      for C of S loop
         if C not in '0' .. '9' then
            raise Protocol_Error with
              "HTTP.Request: non-numeric Content-Length """ & S & """";
         end if;
         D := Interfaces.Integer_64 (Character'Pos (C) - Character'Pos ('0'));
         if Result > (Interfaces.Integer_64'Last - D) / 10 then
            raise Protocol_Error with
              "HTTP.Request: Content-Length out of range """ & S & """";
         end if;
         Result := Result * 10 + D;
      end loop;
      return Result;
   end Parse_Byte_Count;

   --  Lowercase hex, no "16#...#", no leading zeros — RFC 7230 §4.1
   --  chunk-size form.
   function To_Hex (N : Natural) return String is
      Hex : constant String := "0123456789abcdef";
      Buf : String (1 .. 16);
      Pos : Natural  := Buf'Last;
      V   : Natural  := N;
   begin
      if N = 0 then
         return "0";
      end if;
      while V > 0 loop
         Buf (Pos) := Hex (Hex'First + (V mod 16));
         V   := V / 16;
         Pos := Pos - 1;
      end loop;
      return Buf (Pos + 1 .. Buf'Last);
   end To_Hex;

   --  Head section shared by Write and Write_Streaming: request line +
   --  caller headers (stored lowercase, insertion order) + an optional
   --  synthesised framing header + the blank-line terminator. Universal
   --  anti-smuggling validation (RFC 7230 §3.3.3): caller Transfer-
   --  Encoding is rejected (the chunked encoder owns it) and a duplicate
   --  Content-Length is rejected. Returns the head; writes nothing, so a
   --  validation failure leaves the wire untouched. Extra_Name = "" adds
   --  no synthesised header.
   function Build_Head
     (Self        : Request_Type;
      Extra_Name  : String := "";
      Extra_Value : String := "") return String
   is
      Buf : Unbounded_String;

      procedure Emit_Stored (Name, Value : String) is
      begin
         Append (Buf, Name & ": " & Value & CRLF);
      end Emit_Stored;
   begin
      if Self.Headers.Contains ("transfer-encoding") then
         raise Protocol_Error with
           "HTTP.Request: Transfer-Encoding is owned by the streaming "
           & "encoder; do not set it (use Write_Streaming without a "
           & "Content-Length for chunked upload)";
      end if;

      if Natural (Self.Headers.Values ("content-length").Length) > 1 then
         raise Protocol_Error with
           "HTTP.Request: duplicate Content-Length (request-smuggling "
           & "hazard)";
      end if;

      Append (Buf, AHT.HTTP.Methods.Image (Self.Method));
      Append (Buf, " ");
      Append (Buf, AHT.URL.Request_Target (Self.Target));
      Append (Buf, " HTTP/1.1");
      Append (Buf, CRLF);

      Self.Headers.Iterate (Emit_Stored'Access);

      if Extra_Name /= "" then
         Emit_Stored (Extra_Name, Extra_Value);
      end if;

      Append (Buf, CRLF);
      return To_String (Buf);
   end Build_Head;

   procedure Set_Body (Self : in out Request_Type; Text : String) is
   begin
      Self.Body_B.Set (Text);
   end Set_Body;

   procedure Set_Content_Length (Self : in out Request_Type; N : Byte_Count) is
   begin
      Self.Headers.Set ("content-length", Image_64 (N));
   end Set_Content_Length;

   procedure Write
     (Self : Request_Type;
      T    : in out AHT.Transport.Transport_Type'Class)
   is
      CL_Count : constant Natural :=
        Natural (Self.Headers.Values ("content-length").Length);
   begin
      --  A single caller Content-Length must match the buffered body; a
      --  declared-vs-actual mismatch is a framing lie. (A duplicate is
      --  rejected by Build_Head; this parse only runs when there is
      --  exactly one value.)
      if CL_Count = 1
        and then Parse_Byte_Count (Self.Headers.Get ("content-length"))
                 /= Byte_Count (Self.Body_B.Length)
      then
         raise Protocol_Error with
           "HTTP.Request.Write: Content-Length ("
           & Self.Headers.Get ("content-length")
           & ") does not match body length" & Self.Body_B.Length'Image;
      end if;

      declare
         Head : constant String :=
           (if Self.Body_B.Length > 0 and then CL_Count = 0
            then Build_Head
                   (Self, "content-length",
                    Image_No_Space (Self.Body_B.Length))
            else Build_Head (Self));
      begin
         AHT.HTTP.IO.Write_All (T, AHT.Bytes.From_String (Head));
      end;

      --  Body straight from the buffer to the socket: Query hands the
      --  sink a view of the live bytes, so there's no array rebuild.
      if Self.Body_B.Length > 0 then
         declare
            procedure Emit_Body (Data : AHT.Bytes.Byte_Array) is
            begin
               AHT.HTTP.IO.Write_All (T, Data);
            end Emit_Body;
         begin
            Self.Body_B.Query (Emit_Body'Access);
         end;
      end if;
   end Write;

   procedure Write_Streaming
     (Self        : Request_Type;
      T           : in out AHT.Transport.Transport_Type'Class;
      Source      : in out Body_Source'Class;
      Abort_Check : access function return Boolean := null)
   is
      CL_Count : constant Natural :=
        Natural (Self.Headers.Values ("content-length").Length);

      Window : AHT.Bytes.Byte_Array (1 .. Window_Max);
      Last   : Natural;

      function Should_Abort return Boolean is
        (Abort_Check /= null and then Abort_Check.all);

      procedure Check_Abort is
      begin
         if Should_Abort then
            raise AHT.Transport.Aborted_Error with
              "HTTP.Request.Write_Streaming: aborted mid-upload";
         end if;
      end Check_Abort;
   begin
      if CL_Count >= 1 then
         --  Fixed framing. Build_Head emits the caller's single
         --  Content-Length (and rejects a duplicate / a TE header before
         --  anything is written); we stream exactly N bytes.
         declare
            Head : constant String  := Build_Head (Self);
            N    : constant Byte_Count :=
              Parse_Byte_Count (Self.Headers.Get ("content-length"));
            Sent : Byte_Count := 0;
         begin
            AHT.HTTP.IO.Write_All (T, AHT.Bytes.From_String (Head));
            loop
               Check_Abort;
               Source.Read_Chunk (Window, Last);
               if Last < Window'First then
                  if Sent < N then
                     raise Protocol_Error with
                       "HTTP.Request.Write_Streaming: source under-ran "
                       & "Content-Length (" & Image_64 (Sent) & " of "
                       & Image_64 (N) & " bytes)";
                  end if;
                  exit;
               end if;
               declare
                  Got : constant Byte_Count :=
                    Byte_Count (Last - Window'First + 1);
               begin
                  --  Overflow-safe: Sent <= N <= Byte_Count'Last, so
                  --  N - Sent never overflows, whereas Sent + Got could
                  --  for an N near Byte_Count'Last with a final window.
                  if Got > N - Sent then
                     raise Protocol_Error with
                       "HTTP.Request.Write_Streaming: source over-ran "
                       & "Content-Length (" & Image_64 (N) & " bytes)";
                  end if;
                  AHT.HTTP.IO.Write_All (T, Window (Window'First .. Last));
                  Sent := Sent + Got;
               end;
               --  No `exit when Sent = N`: once N bytes are sent we loop
               --  back for one more Read_Chunk so a source that summed to
               --  exactly N across windows but still has bytes queued is
               --  caught as an over-run (the next window trips the guard
               --  above), not silently truncated. A well-behaved source
               --  signals EOF here and the Last < Window'First branch exits.
            end loop;
         end;
      else
         --  Chunked framing: the encoder owns Transfer-Encoding.
         declare
            Head : constant String :=
              Build_Head (Self, "transfer-encoding", "chunked");
         begin
            AHT.HTTP.IO.Write_All (T, AHT.Bytes.From_String (Head));
            loop
               Check_Abort;
               Source.Read_Chunk (Window, Last);
               exit when Last < Window'First;
               AHT.HTTP.IO.Write_All
                 (T,
                  AHT.Bytes.From_String
                    (To_Hex (Last - Window'First + 1) & CRLF));
               AHT.HTTP.IO.Write_All (T, Window (Window'First .. Last));
               AHT.HTTP.IO.Write_All (T, AHT.Bytes.From_String (CRLF));
            end loop;
            AHT.HTTP.IO.Write_All
              (T, AHT.Bytes.From_String ("0" & CRLF & CRLF));
         end;
      end if;
   end Write_Streaming;

end AHT.HTTP.Request;
