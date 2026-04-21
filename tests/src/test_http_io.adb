with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;

with AHT.Bytes;
with AHT.HTTP;
with AHT.HTTP.IO;
with AHT.Transport;

procedure Test_HTTP_IO is

   use type Interfaces.Unsigned_8;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_io: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Mock transport: feeds Read from a pre-loaded script (Natural
   --  array so we can distinguish "nothing" from a zero byte), and
   --  captures Write calls in a growing Byte_Vector. Read honours an
   --  optional Chunk_Size cap so tests can force Read_N to loop.

   type Transport is new AHT.Transport.Transport_Type with record
      Script     : AHT.Bytes.Byte_Vector;
      Cursor     : Positive := 1;
      Chunk_Size : Positive := Positive'Last;
      Written    : AHT.Bytes.Byte_Vector;
      Open       : Boolean  := True;
   end record;

   overriding procedure Write
     (Self : in out Transport;
      Data : AHT.Bytes.Byte_Array);

   overriding procedure Read
     (Self : in out Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);

   overriding procedure Close (Self : in out Transport);

   overriding function Is_Connected (Self : Transport) return Boolean;

   overriding procedure Write
     (Self : in out Transport;
      Data : AHT.Bytes.Byte_Array) is
   begin
      for B of Data loop
         Self.Written.Append (B);
      end loop;
   end Write;

   overriding procedure Read
     (Self : in out Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      Remaining : constant Natural :=
        Natural (Self.Script.Length) - (Self.Cursor - 1);
      N         : Natural := Remaining;
   begin
      if Remaining = 0 then
         Last := 0;
         return;
      end if;
      if N > Data'Length then N := Data'Length; end if;
      if N > Self.Chunk_Size then N := Self.Chunk_Size; end if;
      for I in 0 .. N - 1 loop
         Data (Data'First + I) := Self.Script (Self.Cursor + I);
      end loop;
      Self.Cursor := Self.Cursor + N;
      Last := Data'First + N - 1;
   end Read;

   overriding procedure Close (Self : in out Transport) is
   begin
      Self.Open := False;
   end Close;

   overriding function Is_Connected (Self : Transport) return Boolean is
     (Self.Open);

   --  Load a String into Script as raw bytes.
   procedure Load (T : in out Transport; S : String) is
   begin
      T.Script.Clear;
      T.Cursor := 1;
      for C of S loop
         T.Script.Append (Character'Pos (C));
      end loop;
   end Load;

   --  Compare captured Written bytes to an expected String.
   function Written_Equals (T : Transport; S : String) return Boolean is
   begin
      if Natural (T.Written.Length) /= S'Length then return False; end if;
      for I in S'Range loop
         if T.Written (T.Written.First_Index + (I - S'First))
            /= Character'Pos (S (I))
         then
            return False;
         end if;
      end loop;
      return True;
   end Written_Equals;

   function Vector_To_String (V : AHT.Bytes.Byte_Vector) return String is
      S : String (1 .. Natural (V.Length));
   begin
      for I in S'Range loop
         declare
            B : constant AHT.Bytes.Octet := V.Element (V.First_Index + (I - 1));
         begin
            S (I) := Character'Val (Natural (B));
         end;
      end loop;
      return S;
   end Vector_To_String;

begin
   --  Case 1: Write_All forwards bytes verbatim; empty is a no-op.
   declare
      T : Transport;
   begin
      AHT.HTTP.IO.Write_All (T, AHT.Bytes.From_String ("GET / HTTP/1.1" & ASCII.CR & ASCII.LF));
      if not Written_Equals (T, "GET / HTTP/1.1" & ASCII.CR & ASCII.LF) then
         Fail ("write_all: captured bytes differ from input");
      end if;
      AHT.HTTP.IO.Write_All (T, AHT.Bytes.Byte_Array'(1 .. 0 => 0));
      if Natural (T.Written.Length) /= 16 then
         Fail ("write_all: empty slice should be a no-op");
      end if;
   end;

   --  Case 2: Read_Line returns the line without CRLF, and consumes
   --  exactly the CRLF (a second Read_Line sees only what follows).
   declare
      T : Transport;
   begin
      Load (T, "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
               & "Content-Length: 3" & ASCII.CR & ASCII.LF
               & ASCII.CR & ASCII.LF
               & "abc");
      declare
         L1 : constant String := AHT.HTTP.IO.Read_Line (T);
         L2 : constant String := AHT.HTTP.IO.Read_Line (T);
         L3 : constant String := AHT.HTTP.IO.Read_Line (T);
      begin
         if L1 /= "HTTP/1.1 200 OK" then
            Fail ("read_line: status = """ & L1 & """");
         end if;
         if L2 /= "Content-Length: 3" then
            Fail ("read_line: header = """ & L2 & """");
         end if;
         if L3'Length /= 0 then
            Fail ("read_line: blank line had length" & L3'Length'Image);
         end if;
      end;
   end;

   --  Case 3: Read_Line raises Protocol_Error on EOF before CRLF.
   declare
      T : Transport;
   begin
      Load (T, "no crlf here");
      begin
         declare
            Junk : constant String := AHT.HTTP.IO.Read_Line (T);
         begin
            Fail ("read_line: EOF should have raised, got """ & Junk & """");
         end;
      exception
         when AHT.HTTP.Protocol_Error => null;
         when E : others =>
            Fail ("read_line: EOF raised wrong exception: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 4: Read_Line raises Protocol_Error past Max_Length.
   declare
      T : Transport;
   begin
      Load (T, "0123456789abcdef" & ASCII.CR & ASCII.LF);
      begin
         declare
            Junk : constant String := AHT.HTTP.IO.Read_Line (T, Max_Length => 8);
         begin
            Fail ("read_line: length cap should have raised, got """
                  & Junk & """");
         end;
      exception
         when AHT.HTTP.Protocol_Error => null;
         when E : others =>
            Fail ("read_line: length cap raised wrong exception: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 5: Read_N fills across multiple underlying reads, with
   --  Chunk_Size = 1 forcing the worst case.
   declare
      T : Transport;
      D : AHT.Bytes.Byte_Array (1 .. 5);
   begin
      Load (T, "hello");
      T.Chunk_Size := 1;
      AHT.HTTP.IO.Read_N (T, D);
      if AHT.Bytes.To_String (D) /= "hello" then
         Fail ("read_n: assembled = """ & AHT.Bytes.To_String (D) & """");
      end if;
   end;

   --  Case 6: Read_N with zero-length slice is a no-op and does not
   --  consume script bytes.
   declare
      T : Transport;
      D : AHT.Bytes.Byte_Array (1 .. 0);
   begin
      Load (T, "abc");
      AHT.HTTP.IO.Read_N (T, D);
      if T.Cursor /= 1 then
         Fail ("read_n: empty slice advanced cursor to" & T.Cursor'Image);
      end if;
   end;

   --  Case 7: Read_N raises Protocol_Error if peer closes mid-read.
   declare
      T : Transport;
      D : AHT.Bytes.Byte_Array (1 .. 8);
   begin
      Load (T, "abc");
      begin
         AHT.HTTP.IO.Read_N (T, D);
         Fail ("read_n: short stream should have raised");
      exception
         when AHT.HTTP.Protocol_Error => null;
         when E : others =>
            Fail ("read_n: short stream raised wrong exception: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 8: Read_Chunked_Body reassembles multi-chunk bodies and
   --  stops at the zero-size chunk (no trailers).
   declare
      T : Transport;
   begin
      Load (T,
            "5" & ASCII.CR & ASCII.LF & "Hello" & ASCII.CR & ASCII.LF
            & "6" & ASCII.CR & ASCII.LF & ", Ada" & Character'Val (33)
            & ASCII.CR & ASCII.LF
            & "0" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF);
      declare
         V : constant AHT.Bytes.Byte_Vector := AHT.HTTP.IO.Read_Chunked_Body (T);
      begin
         if Vector_To_String (V) /= "Hello, Ada!" then
            Fail ("chunked: assembled = """
                  & Vector_To_String (V) & """");
         end if;
      end;
   end;

   --  Case 9: chunk-ext after the size is ignored; hex size is
   --  accepted in upper case.
   declare
      T : Transport;
   begin
      Load (T,
            "A;name=value" & ASCII.CR & ASCII.LF
            & "0123456789" & ASCII.CR & ASCII.LF
            & "0" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF);
      declare
         V : constant AHT.Bytes.Byte_Vector := AHT.HTTP.IO.Read_Chunked_Body (T);
      begin
         if Vector_To_String (V) /= "0123456789" then
            Fail ("chunk-ext: body = """ & Vector_To_String (V) & """");
         end if;
      end;
   end;

   --  Case 10: trailer headers after the zero-size chunk are
   --  consumed until a bare CRLF.
   declare
      T : Transport;
   begin
      Load (T,
            "3" & ASCII.CR & ASCII.LF & "abc" & ASCII.CR & ASCII.LF
            & "0" & ASCII.CR & ASCII.LF
            & "X-Trailer: one" & ASCII.CR & ASCII.LF
            & "X-Other: two"   & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF);
      declare
         V : constant AHT.Bytes.Byte_Vector := AHT.HTTP.IO.Read_Chunked_Body (T);
      begin
         if Vector_To_String (V) /= "abc" then
            Fail ("trailer: body = """ & Vector_To_String (V) & """");
         end if;
         --  Script must be fully consumed.
         if T.Cursor - 1 /= Natural (T.Script.Length) then
            Fail ("trailer: cursor at" & T.Cursor'Image
                  & " of" & Natural (T.Script.Length)'Image
                  & " — trailer section not fully drained");
         end if;
      end;
   end;

   --  Case 11: non-hex size raises Protocol_Error.
   declare
      T : Transport;
   begin
      Load (T, "xyz" & ASCII.CR & ASCII.LF);
      begin
         declare
            V : constant AHT.Bytes.Byte_Vector := AHT.HTTP.IO.Read_Chunked_Body (T);
            pragma Unreferenced (V);
         begin
            Fail ("bad-hex: should have raised");
         end;
      exception
         when AHT.HTTP.Protocol_Error => null;
         when E : others =>
            Fail ("bad-hex: raised wrong exception: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 12: missing CRLF after chunk-data raises Protocol_Error.
   declare
      T : Transport;
   begin
      Load (T,
            "3" & ASCII.CR & ASCII.LF & "abcXY" & ASCII.CR & ASCII.LF
            & "0" & ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF);
      begin
         declare
            V : constant AHT.Bytes.Byte_Vector := AHT.HTTP.IO.Read_Chunked_Body (T);
            pragma Unreferenced (V);
         begin
            Fail ("bad-crlf: should have raised");
         end;
      exception
         when AHT.HTTP.Protocol_Error => null;
         when E : others =>
            Fail ("bad-crlf: raised wrong exception: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   if Failures = 0 then
      Put_Line ("test_http_io: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_io:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_IO;
