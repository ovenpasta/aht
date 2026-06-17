--  Example 3 — streaming a large body without buffering it.
--
--  `Send` accumulates the whole response body in `Resp.Body_B`. For a
--  big download that means holding the entire thing in memory. The
--  streaming variant hands each slice to a `Sink` callback as it
--  arrives, so you can process (write to disk, hash, count) on the fly
--  and never materialise the full body. `Resp.Body_B` comes back empty.
--
--  Two passes here, both against the fixture's /chunked-big route (a
--  13 MB ramp delivered in one chunked frame):
--    * push style — a Sink callback tallies bytes and prints a line per
--      megabyte. The many progress lines show the body really is arriving
--      in windowed slices, not one allocation.
--    * stream-target style (the library-provided, no-callback way) —
--      hand Send_Streaming an Ada stream as the Target and the body is
--      written straight there. Here the Target is a temp file's stream,
--      so the download lands on disk with no sink to write yourself --
--      the download mirror of ex_05's Stream_Source upload.
--
--  Run:  ./examples/bin/ex_03_streaming [URL]
--  URL defaults to the fixture's /chunked-big; pass any URL to a large
--  body to retarget.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;

procedure Ex_03_Streaming is

   Default_URL : constant String := "http://127.0.0.1:8764/chunked-big";

   URL : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_URL);

   Client : AHT.HTTP.Client.Client_Type;
   Req    : AHT.HTTP.Request.Request_Type;
   Resp   : AHT.HTTP.Response.Response_Type;

   --  Sink state: total bytes, the next megabyte mark to announce, and
   --  how many times the sink fired (one call per windowed slice).
   Total     : Natural := 0;
   Next_Mark : Natural := 1_000_000;
   Calls     : Natural := 0;

   procedure On_Chunk (Chunk : AHT.Bytes.Byte_Array) is
   begin
      Calls := Calls + 1;
      Total := Total + Chunk'Length;
      if Total >= Next_Mark then
         Put_Line ("  received"
                   & Natural'Image (Total / 1_000_000) & " MB ...");
         Next_Mark := Next_Mark + 1_000_000;
      end if;
   end On_Chunk;

begin
   --  Pass 1 — push style: process each slice in a Sink callback.
   Put_Line ("GET (streaming, Sink) " & URL);
   Req.Method := AHT.HTTP.Methods.GET;
   Req.Target := AHT.URL.Parse (URL);

   AHT.HTTP.Client.Send_Streaming
     (Client, Req, Resp, Sink => On_Chunk'Access);

   Put_Line ("  status      : " & Resp.Status'Image);
   Put_Line ("  total bytes :" & Natural'Image (Total));
   Put_Line ("  sink calls  :" & Natural'Image (Calls)
             & " (one per windowed slice)");
   Put_Line ("  buffered    :"
             & Natural'Image (Resp.Body_B.Length)
             & " (body never accumulated)");

   --  Pass 2 — stream-target style: no callback at all. Give
   --  Send_Streaming a Target stream (here a temp file) and the body is
   --  written there directly as it arrives.
   New_Line;
   declare
      Path  : constant String := "/tmp/aht_ex_03_download.bin";
      F     : Ada.Streams.Stream_IO.File_Type;
      Req2  : AHT.HTTP.Request.Request_Type;
      Resp2 : AHT.HTTP.Response.Response_Type;
   begin
      Put_Line ("GET (streaming, Target => file) " & URL);
      Req2.Method := AHT.HTTP.Methods.GET;
      Req2.Target := AHT.URL.Parse (URL);

      Ada.Streams.Stream_IO.Create
        (F, Ada.Streams.Stream_IO.Out_File, Path);
      AHT.HTTP.Client.Send_Streaming
        (Client, Req2, Resp2,
         Target => Ada.Streams.Stream_IO.Stream (F));
      Ada.Streams.Stream_IO.Close (F);

      Put_Line ("  status     : " & Resp2.Status'Image);
      Put_Line ("  saved to   : " & Path);
      Put_Line ("  file bytes :"
                & Ada.Directories.File_Size'Image
                    (Ada.Directories.Size (Path))
                & " (written straight to disk, no sink)");
      Ada.Directories.Delete_File (Path);
   end;

   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("request failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the fixture up? try: bash examples/run_examples.sh)");
      Set_Exit_Status (Failure);
end Ex_03_Streaming;
