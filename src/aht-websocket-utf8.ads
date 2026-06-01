with AHT.Bytes;

package AHT.Websocket.UTF8 is

   pragma Preelaborate;

   --  RFC 3629 well-formedness check for UTF-8.
   --
   --  A WebSocket text message — and the reason text of a Close frame —
   --  MUST be valid UTF-8; an endpoint that receives an ill-formed one
   --  fails the connection with close code 1007 (RFC 6455 §8.1). These
   --  predicates answer "is the *complete* byte sequence well-formed
   --  UTF-8?", so a multi-byte sequence truncated at the end counts as
   --  invalid (there are no more bytes coming to finish it).
   --
   --  "Well-formed" here is the strict RFC 3629 definition, which the
   --  Autobahn|Testsuite §6 cases enforce:
   --    * only 1..4-byte sequences (no 5/6-byte forms),
   --    * no overlong encodings,
   --    * no UTF-16 surrogate halves (U+D800 .. U+DFFF),
   --    * nothing above U+10FFFF.

   function Is_Valid (Data : AHT.Bytes.Byte_Array)  return Boolean;
   function Is_Valid (Data : AHT.Bytes.Byte_Vector) return Boolean;

end AHT.Websocket.UTF8;
