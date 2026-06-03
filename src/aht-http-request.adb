with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with AHT.HTTP.IO;

package body AHT.HTTP.Request is

   function Image_No_Space (N : Natural) return String is
     (Ada.Strings.Fixed.Trim (Natural'Image (N), Ada.Strings.Left));

   procedure Set_Body (Self : in out Request_Type; Text : String) is
   begin
      Self.Body_B.Clear;
      Self.Body_B.Reserve_Capacity (Text'Length);
      for C of Text loop
         Self.Body_B.Append (Character'Pos (C));
      end loop;
   end Set_Body;

   procedure Write
     (Self : Request_Type;
      T    : in out AHT.Transport.Transport_Type'Class)
   is
      Buf : Unbounded_String;

      procedure Put (S : String) is
      begin
         Append (Buf, S);
      end Put;

      procedure Put_CRLF is
      begin
         Append (Buf, ASCII.CR & ASCII.LF);
      end Put_CRLF;

      procedure Emit_Header (Name, Value : String) is
      begin
         Put (Name);
         Put (": ");
         Put (Value);
         Put_CRLF;
      end Emit_Header;

      procedure Emit_Stored (Name, Value : String) is
      begin
         Emit_Header (Name, Value);
      end Emit_Stored;
   begin
      --  Request line: METHOD SP target SP HTTP/1.1 CRLF.
      Put (AHT.HTTP.Methods.Image (Self.Method));
      Put (" ");
      Put (AHT.URL.Request_Target (Self.Target));
      Put (" HTTP/1.1");
      Put_CRLF;

      --  v1 does not support Transfer-Encoding on outbound requests:
      --  Request.Write emits Body_B as raw bytes, which would be
      --  malformed against a chunked framing header. Fail loudly
      --  instead of producing invalid-but-plausible wire bytes.
      --  The streaming-upload API that will own chunked request
      --  bodies is a separate surface still to land.
      if Self.Headers.Contains ("transfer-encoding") then
         raise Protocol_Error with
           "HTTP.Request.Write: Transfer-Encoding on requests is not "
           & "supported; use Content-Length (auto-added if absent)";
      end if;

      --  Caller-supplied headers, in insertion order, lowercase names.
      Self.Headers.Iterate (Emit_Stored'Access);

      --  Synthesise Content-Length if the caller didn't already
      --  frame the body explicitly. Without this a request with a
      --  body and no Content-Length is a protocol error — easy to
      --  forget, cheap to fix here.
      if Natural (Self.Body_B.Length) > 0
        and then not Self.Headers.Contains ("content-length")
      then
         Emit_Header
           ("content-length",
            Image_No_Space (Natural (Self.Body_B.Length)));
      end if;

      --  Blank line ends the head section.
      Put_CRLF;

      AHT.HTTP.IO.Write_All (T, AHT.Bytes.From_String (To_String (Buf)));

      if Natural (Self.Body_B.Length) > 0 then
         declare
            Body_Bytes : AHT.Bytes.Byte_Array
              (1 .. Natural (Self.Body_B.Length));
         begin
            for I in Body_Bytes'Range loop
               Body_Bytes (I) :=
                 Self.Body_B.Element (Self.Body_B.First_Index + (I - 1));
            end loop;
            AHT.HTTP.IO.Write_All (T, Body_Bytes);
         end;
      end if;
   end Write;

end AHT.HTTP.Request;
