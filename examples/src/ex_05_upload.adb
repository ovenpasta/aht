--  Example 5 — streaming a request body up from disk, no buffering.
--
--  A small POST/PUT body? `Set_Body` is enough. But to upload a file --
--  maybe gigabytes -- without slurping it into memory, stream it: the
--  client pulls the body in fixed windows from a `Body_Source`. You used
--  to hand-write that source; `AHT.HTTP.Request.Sources.Stream_Source`
--  wraps any Ada stream (a file via `Stream_IO`, a socket, a generator)
--  as one, so a file upload is a few lines.
--
--  Framing is header-driven: set `Content-Length` for fixed framing
--  (done here from the file's size), or omit it to send
--  `Transfer-Encoding: chunked`. The source never buffers the body.
--
--  Here we stage a small temp file, stream it to /echo (which reflects
--  the body back), and print what returned -- proving the bytes made the
--  trip while the body was never held in a buffer. This is the upload
--  mirror of ex_03's stream-Target download.
--
--  Run:  ./examples/bin/ex_05_upload [URL]
--  URL defaults to the fixture's /echo; point it at e.g. a go-httpbin
--  /post to try it elsewhere (drop Set_Content_Length there for a
--  chunked upload).

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Request.Sources;
with AHT.HTTP.Response;
with AHT.URL;

procedure Ex_05_Upload is

   Default_URL : constant String := "http://127.0.0.1:8764/echo";

   URL : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_URL);

   Path : constant String := "/tmp/aht_ex_05_upload.txt";

   Client : AHT.HTTP.Client.Client_Type;
   Req    : AHT.HTTP.Request.Request_Type;
   Resp   : AHT.HTTP.Response.Response_Type;

   Payload : constant String :=
     "streamed straight from a file on disk" & ASCII.LF;
begin
   --  Stage a file to upload. In real use this is whatever file you
   --  already have -- the point is it is never read into memory here.
   declare
      F : Ada.Streams.Stream_IO.File_Type;
   begin
      Ada.Streams.Stream_IO.Create
        (F, Ada.Streams.Stream_IO.Out_File, Path);
      String'Write (Ada.Streams.Stream_IO.Stream (F), Payload);
      Ada.Streams.Stream_IO.Close (F);
   end;

   Put_Line ("POST (streaming upload) " & URL);
   Put_Line ("  uploading " & Path & " ("
             & Ada.Directories.File_Size'Image (Ada.Directories.Size (Path))
             & " bytes)");

   Req.Method := AHT.HTTP.Methods.POST;
   Req.Target := AHT.URL.Parse (URL);
   Req.Headers.Set ("content-type", "text/plain");
   --  Fixed framing: announce how many bytes are coming. (Omit this line
   --  to send Transfer-Encoding: chunked instead.)
   Req.Set_Content_Length
     (AHT.HTTP.Request.Byte_Count (Ada.Directories.Size (Path)));

   --  Open the file and wrap its stream as a Stream_Source. The source
   --  borrows the stream, so we keep the file open across the call.
   declare
      F : Ada.Streams.Stream_IO.File_Type;
   begin
      Ada.Streams.Stream_IO.Open
        (F, Ada.Streams.Stream_IO.In_File, Path);
      declare
         Src : AHT.HTTP.Request.Sources.Stream_Source :=
                 AHT.HTTP.Request.Sources.Create
                   (Ada.Streams.Stream_IO.Stream (F));
      begin
         AHT.HTTP.Client.Send_Streaming_Body (Client, Req, Resp, Src);
      end;
      Ada.Streams.Stream_IO.Close (F);
   end;

   Ada.Directories.Delete_File (Path);

   Put_Line ("  status : " & Resp.Status'Image);
   Put_Line ("  echoed : " & Resp.Body_Text);
   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("upload failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the fixture up? try: bash examples/run_examples.sh)");
      Set_Exit_Status (Failure);
end Ex_05_Upload;
