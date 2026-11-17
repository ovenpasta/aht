<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# DEFLATE decoder

Package `AHT.Inflate`, with the private child `AHT.Inflate.Huffman`.
It decodes the bodies `AHT.HTTP.Response` decompresses for the `gzip`
and `deflate` content codings, and has no HTTP knowledge of its own.

```ada
Data_Error : exception;
type Format is (Raw, Zlib, Zlib_Or_Raw, Gzip);

procedure Decode
  (Kind   : Format;
   Input  : not null access procedure
     (Data : out AHT.Bytes.Byte_Array; Last : out Natural);
   Output : not null access procedure (Data : AHT.Bytes.Byte_Array));
```

## Provenance

The block decoder comes from Zip-Ada 62 (Gautier de Montmollin,
<https://unzip-ada.sourceforge.io>), MIT licensed: the bit reader,
the Huffman table construction (`UnZip.Decompress.Huffman`, itself
from info-zip), the stored / fixed / dynamic block decoders and the
sliding-window copy of `UnZip.Decompress`. Zip-Ada's decoder is private
to its archive reader and pulls from a seekable zip stream, so it is
vendored rather than depended on. Both files carry Zip-Ada's copyright
and the MIT licence; `LICENSES/MIT.txt` holds the text.

Changed from Zip-Ada:

- Input is a callback, output is a callback; there is no archive,
  file or encryption layer, and Deflate64 and the other zip methods
  are gone.
- A truncated stream is an error. Zip-Ada knows the compressed size
  and lets the decoder run on into the buffer past it; here the bit
  reader may borrow at most four zero bytes past the end of input (a
  Huffman lookup reads its full index width even when the code is
  shorter, which at the end of a stream needs up to two). A stream
  that borrows more, or ends having consumed borrowed bits, raises
  `Data_Error` reporting truncation.
- A back-reference is checked against the output produced so far. In
  a zip archive a bad distance is caught by the CRC; a raw `deflate`
  body has no checksum.
- Dynamic blocks are held to the RFC 1951 limits (286 literal/length
  and 30 distance codes) and incomplete code sets are refused, as zlib
  does.
- Huffman tables are owned by a controlled holder, so a decode that
  unwinds (corrupt data, an exception from `Input` such as a transport
  timeout, an abort) frees what it built.
- The zlib (RFC 1950) and gzip (RFC 1952) framings and their checks
  are new.

## Behaviour

- `Input` fills `Data (Data'First .. Last)` with at least one byte or
  signals the end with `Last < Data'First`; it is not called again
  after that. The whole input is consumed: the decode continues until
  `Input` reports the end, and a byte after the end of the stream is
  `Data_Error`.
- `Output` receives the decoded bytes in order, as non-empty slices of
  at most 4 KiB. Pending output is delivered before every call to
  `Input`, so a decoded byte never waits on more network input; the
  32 KiB window is a history, not a buffer.
- `Raw` is a bare DEFLATE stream. `Zlib` checks the two-byte header,
  refuses a preset dictionary and checks the big-endian Adler-32.
  `Gzip` accepts one or more members, skips `FEXTRA`, `FNAME` and
  `FCOMMENT`, checks `FHCRC` when present, and checks each member's
  CRC-32 and length. `Zlib_Or_Raw` looks at the first two bytes: a
  valid zlib header selects `Zlib`, anything else `Raw`. That is how
  HTTP's `deflate` is read, since servers send both.
- An input with no bytes decodes to nothing in every format.
- Exceptions raised by `Input` or `Output` propagate unchanged; only
  the decoder's own findings are `Data_Error`.
- The decoder does not bound its output; DEFLATE expands up to about
  1000 to 1. The caller bounds it in `Output`, as
  `AHT.HTTP.Response` does with its `Max_Decoded` parameter.

## Tests

`tests/src/test_inflate.adb` decodes bodies compressed by Python's
zlib (served by the HTTP fixture, see `/coded` in
`tests/server/server.py`) with input windows of 1, 13 and 4 096 bytes
and compares against the uncompressed originals. The variants reach
stored, fixed and dynamic blocks, a back-reference near the 32 KiB
limit, overlapping copies, every gzip header field and a two-member
stream. Corruptions are applied by the test to zlib's output. The
distance check, the borrowed-bit check, the CRC check and delivery
before each pull each have a case that fails without them.
`tests/src/test_http_decompress.adb` covers the same codings through
the client, under every body framing.
