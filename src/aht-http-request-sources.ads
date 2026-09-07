--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Streams;

with AHT.Bytes;

package AHT.HTTP.Request.Sources is

   --  Streams a request body from any Ada stream -- a file (via
   --  Ada.Streams.Stream_IO.Stream), a socket, an in-memory stream, a
   --  generator -- without ever buffering it, so a caller need not
   --  hand-roll a Body_Source + Read_Chunk for the common "send this
   --  stream" case. Ada.Streams.Read already uses the same pull-fill,
   --  short-Last-at-EOF convention Read_Chunk wants, so Stream_Source is a
   --  thin delegate.
   --
   --  The source *borrows* the stream (it holds an access, not a copy): the
   --  caller owns the stream's open/close lifetime and must keep it alive
   --  across the synchronous Send_Streaming_Body / Write_Streaming call.
   --  That holds by construction -- the call drives the whole upload and
   --  returns before the source (and the stream it points at) goes out of
   --  scope, the same reasoning that makes Send_Streaming_Body's
   --  Source'Access safe.
   --
   --  Framing is header-driven and untouched by the source: a generic
   --  stream has no length, so for fixed framing set Content-Length on the
   --  request yourself (e.g. Set_Content_Length
   --  (Byte_Count (Ada.Directories.Size (Path))) for a file); omit it for
   --  Transfer-Encoding: chunked.
   --  Indefinite (unknown-discriminant) partial view: there is no valid
   --  default Stream_Source -- the only way to make one is Create, which
   --  installs the borrowed stream. This makes "Src : Stream_Source;"
   --  (which would leave Stream null and fault on the first Read_Chunk) a
   --  compile error rather than a runtime trap, statically forcing
   --  construction through Create.
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
