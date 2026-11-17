--  Copyright (C) 2007-2025 Gautier de Montmollin
--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: MIT

--  Streaming DEFLATE decoder (RFC 1951) with the zlib (RFC 1950) and
--  gzip (RFC 1952) framings, for HTTP content codings.
--
--  The block decoder is derived from the Inflate method of
--  UnZip.Decompress in Zip-Ada 62 (https://unzip-ada.sourceforge.io),
--  MIT licensed. Its bit reader, Huffman decoding and sliding-window
--  copy are Zip-Ada's. What is ours: the input is pulled from a
--  callback instead of a zip archive, output is pushed to a callback
--  as it is produced, back-references are checked against the output
--  produced so far, a truncated stream is detected instead of being
--  padded, and the zlib and gzip framings with their checksums.

with AHT.Bytes;

package AHT.Inflate is

   Data_Error : exception;
   --  The compressed stream is malformed, truncated, followed by
   --  trailing bytes, or fails its checksum or length check.

   type Format is
     (Raw,
      --  A bare DEFLATE stream.
      Zlib,
      --  RFC 1950: two-byte header, DEFLATE, big-endian Adler-32.
      --  A preset dictionary (FDICT) is refused.
      Zlib_Or_Raw,
      --  Zlib when the first two bytes form a valid zlib header,
      --  otherwise Raw. What servers send as Content-Encoding:
      --  deflate is either, so this is the HTTP "deflate" decoder.
      Gzip);
      --  RFC 1952: one or more members, each a header (optional
      --  FEXTRA, FNAME, FCOMMENT and FHCRC fields, the last
      --  verified), DEFLATE, then CRC-32 and the length mod 2**32.

   procedure Decode
     (Kind   : Format;
      Input  : not null access procedure
        (Data : out AHT.Bytes.Byte_Array; Last : out Natural);
      Output : not null access procedure (Data : AHT.Bytes.Byte_Array));
   --  Decodes the whole compressed stream Input yields. Input fills
   --  Data (Data'First .. Last) with the next bytes, at least one, or
   --  signals end of input with Last < Data'First; it is not called
   --  again after that. Every input byte is consumed: the decode
   --  continues until Input signals the end, and a byte past the end
   --  of the (last) stream raises Data_Error.
   --
   --  Output receives the decoded bytes in order, as non-empty slices
   --  of at most 4 KiB. Pending output is delivered before each call
   --  to Input, so nothing decoded waits on further input.
   --
   --  An input with no bytes at all decodes to nothing, in every
   --  format. Raises Data_Error as described above; for a stream that
   --  ends early the message says "truncated", whatever the missing
   --  bytes would have been. An exception raised by Input or Output
   --  propagates unchanged; nothing the decode allocated outlives the
   --  call.

end AHT.Inflate;
