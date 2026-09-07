--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Streams;

with AHT.Bytes;

package AHT.HTTP.Request.Sources is

   --  Streams a request body from any Ada stream (a file via
   --  Ada.Streams.Stream_IO.Stream, a socket, a generator) without
   --  buffering it. The source borrows the stream: the caller keeps
   --  it open across the synchronous Send_Streaming_Body call.
   --  Framing is header-driven: set Content-Length on the request
   --  for fixed framing, omit it for chunked. The partial view has
   --  unknown discriminants, so a Stream_Source can only be made by
   --  Create; a default one would hold a null stream.
   type Stream_Source (<>) is new Body_Source with private;

   function Create
     (Stream : not null access Ada.Streams.Root_Stream_Type'Class)
      return Stream_Source;

   overriding procedure Read_Chunk
     (Self : in out Stream_Source;
      Buf  : out AHT.Bytes.Byte_Array;
      Last : out Natural);
   --  Reads up to Buf'Length bytes from the borrowed stream into Buf and
   --  sets Last to the index of the last byte written. A zero-element read
   --  is end-of-stream: Last := Buf'First - 1 and EOF is latched, so every
   --  subsequent call keeps signalling EOF (the sticky-EOF contract of
   --  AHT.HTTP.Request.Read_Chunk). A short-but-nonzero read is a normal
   --  partial fill -- the pump calls again, and true EOF surfaces as the
   --  next zero-element read.

private

   --  Read_Chunk reads into a stack Stream_Element_Array sized to the
   --  caller's window (Write_Streaming hands a fixed <= 64 KiB window every
   --  call, so this is allocation-free and O(1)), then block-copies the
   --  Stream_Element bytes into Buf -- Stream_Element'Size = Octet'Size = 8
   --  on every supported target, so the copy is value-preserving.
   type Stream_Source is new Body_Source with record
      Stream : access Ada.Streams.Root_Stream_Type'Class;
      Done   : Boolean := False;
   end record;

end AHT.HTTP.Request.Sources;
