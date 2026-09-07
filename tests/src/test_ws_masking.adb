--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The frame masking key and the handshake nonce must come from the
--  strong entropy source (RFC 6455 5.3 and 4.1). A real client runs
--  against a fake peer that completes the handshake and parses frames;
--  the masks and nonces read off the socket are paired with the
--  entropy requests AHT.Random counted while the frames went out.
--
--  Cases:
--    1. wire: masks and nonces emitted, entropy requests counted
--    2. source: full byte range appears, output not constant
--
--  Covers:
--    - a call site stops calling AHT.Random, or calls it for the wrong
--      width: both counters move
--    - a PRNG re-seeded on every call: identical nonces across
--      connections, a constant mask, a collapsed byte range
--    - frames are masked at all, the mask is not a constant, nonces
--      differ per connection
--
--  Does not cover:
--    - that the requested bytes became the mask or the nonce: a draw
--      whose result is discarded counts the same as one that ships
--    - AHT.Random replaced by a PRNG seeded once and drawn
--      sequentially: every counter unchanged, and no statistical check
--      on the bytes tells it apart
--    - duplicate masks: 4096 samples collide with probability 0.2% per
--      run, so no duplicate check is used
--    - the source itself, beyond reading it; the width algebra needs
--      redoing if the entropy path grows past two call sites
--
--  Validated by:
--    reverting either production call site to a clock-seeded generator
--    leaves the corresponding width population short in case 1.

with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams; use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets; use GNAT.Sockets;
with GNAT.SHA1;

with AHT.Bytes; use type AHT.Bytes.Octet;
with AHT.Random;
with AHT.Websocket.Client;

procedure Test_WS_Masking is

   Port : constant := 8799;
   URL  : constant String := "ws://127.0.0.1:8799/";

   --  Eight connections of thirty-two frames each. Not a statistical
   --  threshold: large enough that a stuck mask is obvious, spread
   --  over several connections so the nonce is sampled per connection.
   Connections  : constant := 8;
   Frames_Each  : constant := 32;
   Mask_Samples : constant := Connections * Frames_Each;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_masking: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   type Mask_Value is mod 2 ** 32;

   --  Named, because an anonymous array cannot be a protected
   --  component.
   type Mask_Array  is array (1 .. Mask_Samples * 2) of Mask_Value;
   type Nonce_Array is array (1 .. Connections) of Unbounded_String;

   --  Collected by the fake peer, read by the main task once the peer
   --  is done. Protected because the two run concurrently.
   protected Wire is
      procedure Note_Mask (M : Mask_Value);
      procedure Note_Nonce (N : String);
      procedure Note_Error (Msg : String);
      function  Mask_Count return Natural;
      function  Mask_At (I : Positive) return Mask_Value;
      function  Nonce_Count return Natural;
      function  Nonce_At (I : Positive) return String;
      function  Error return String;
   private
      Masks   : Mask_Array;
      N_Masks : Natural := 0;
      Nonces  : Nonce_Array;
      N_Nonce : Natural := 0;
      Err     : Unbounded_String;
   end Wire;

   protected body Wire is
      procedure Note_Mask (M : Mask_Value) is
      begin
         if N_Masks < Masks'Last then
            N_Masks := N_Masks + 1;
            Masks (N_Masks) := M;
         end if;
      end Note_Mask;
      procedure Note_Nonce (N : String) is
      begin
         if N_Nonce < Nonces'Last then
            N_Nonce := N_Nonce + 1;
            Nonces (N_Nonce) := To_Unbounded_String (N);
         end if;
      end Note_Nonce;
      procedure Note_Error (Msg : String) is
      begin
         if Err = Null_Unbounded_String then
            Err := To_Unbounded_String (Msg);
         end if;
      end Note_Error;
      function Mask_Count return Natural is (N_Masks);
      function Mask_At (I : Positive) return Mask_Value is (Masks (I));
      function Nonce_Count return Natural is (N_Nonce);
      function Nonce_At (I : Positive) return String is
        (To_String (Nonces (I)));
      function Error return String is (To_String (Err));
   end Wire;

   --  Handshake helpers (the same computation the client does)

   function Hex_To_Bytes (Hex : String) return AHT.Bytes.Byte_Array is
      function Val (C : Character) return Natural is
        (case C is
           when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
           when 'a' .. 'f' => 10 + Character'Pos (C) - Character'Pos ('a'),
           when 'A' .. 'F' => 10 + Character'Pos (C) - Character'Pos ('A'),
           when others     => raise Program_Error with "bad hex");
      B : AHT.Bytes.Byte_Array (1 .. Hex'Length / 2);
   begin
      for I in 0 .. B'Length - 1 loop
         B (B'First + I) :=
           AHT.Bytes.Octet
             (16 * Val (Hex (Hex'First + 2 * I))
              +    Val (Hex (Hex'First + 2 * I + 1)));
      end loop;
      return B;
   end Hex_To_Bytes;

   function Compute_Accept (Key : String) return String is
      Guid : constant String := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
      Hex  : constant String := GNAT.SHA1.Digest (Key & Guid);
   begin
      return AHT.Bytes.Base64_Encode (Hex_To_Bytes (Hex));
   end Compute_Accept;

   function Extract_Key (Req : String) return String is
      Marker : constant String := "sec-websocket-key:";
      Lower  : constant String := Ada.Characters.Handling.To_Lower (Req);
      Idx    : constant Natural := Ada.Strings.Fixed.Index (Lower, Marker);
      VS, VE : Natural;
   begin
      if Idx = 0 then
         return "";
      end if;
      VS := Idx + Marker'Length;
      VE := Ada.Strings.Fixed.Index
              (Req (VS .. Req'Last), ASCII.CR & ASCII.LF);
      if VE = 0 then
         return "";
      end if;
      return Ada.Strings.Fixed.Trim (Req (VS .. VE - 1), Ada.Strings.Both);
   end Extract_Key;

   --  The fake peer

   --  Ready carries a status: a failed bind raises before `accept
   --  Ready`, and a bare rendezvous would park the main task on Ready
   --  and the peer on Finished. Both entries are on every path and the
   --  main task's calls are timed, so a peer that dies some other way
   --  still produces a report.
   task Peer is
      entry Ready (Listening : out Boolean);
      entry Finished;
   end Peer;

   task body Peer is
      Listener : Socket_Type;
      Conn     : Socket_Type;
      Addr     : Sock_Addr_Type;
      Peer_Adr : Sock_Addr_Type;
      Up       : Boolean := False;
   begin
      begin
         Create_Socket (Listener);
         Set_Socket_Option (Listener, Socket_Level, (Reuse_Address, True));
         --  Bounds Accept_Socket, so a client that never arrives
         --  cannot park this task past the end of the test.
         Set_Socket_Option
           (Listener, Socket_Level, (Receive_Timeout, 20.0));
         Addr := (Family => Family_Inet,
                  Addr   => Inet_Addr ("127.0.0.1"),
                  Port   => Port);
         Bind_Socket (Listener, Addr);
         Listen_Socket (Listener, 16);
         Up := True;
      exception
         when E : others =>
            Wire.Note_Error
              ("could not listen on port" & Integer'Image (Port) & ": "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
      end;

      --  Accepted whether or not the socket came up, with a terminate
      --  alternative: the main task's call is timed, and if it expires
      --  nobody calls Ready again. Every accept in this task needs it.
      select
         accept Ready (Listening : out Boolean) do
            Listening := Up;
         end Ready;
      or
         terminate;
      end select;

      for C in 1 .. (if Up then Connections else 0) loop
         Accept_Socket (Listener, Conn, Peer_Adr);
         declare
            Chan : constant Stream_Access := Stream (Conn);
            Req  : Unbounded_String;
            Ch   : Character;
         begin
            loop
               Character'Read (Chan, Ch);
               Append (Req, Ch);
               exit when Length (Req) >= 4
                 and then Slice (Req, Length (Req) - 3, Length (Req))
                          = ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF;
            end loop;

            declare
               Key : constant String := Extract_Key (To_String (Req));
            begin
               if Key = "" then
                  Wire.Note_Error ("no Sec-WebSocket-Key in the request");
               else
                  Wire.Note_Nonce (Key);
               end if;
               String'Write
                 (Chan,
                  "HTTP/1.1 101 Switching Protocols" & ASCII.CR & ASCII.LF
                  & "Upgrade: websocket" & ASCII.CR & ASCII.LF
                  & "Connection: Upgrade" & ASCII.CR & ASCII.LF
                  & "Sec-WebSocket-Accept: " & Compute_Accept (Key)
                  & ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF);
            end;

            --  Parse frames until the connection dies, taking the
            --  4-byte mask off each; an unmasked frame is a finding
            --  (5.3). Every frame, not Frames_Each: the Close frame
            --  draws a mask too, and a peer that stops early leaves
            --  the draw check below enough slack to hide a missing
            --  nonce draw.
            loop
               declare
                  B0, B1 : Stream_Element;
                  Len    : Natural;
                  Masked : Boolean;
                  M      : Mask_Value := 0;
                  Junk   : Stream_Element;
               begin
                  Stream_Element'Read (Chan, B0);
                  Stream_Element'Read (Chan, B1);
                  Masked := (B1 and 16#80#) /= 0;
                  Len    := Natural (B1 and 16#7F#);
                  if Len = 126 then
                     Len := 0;
                     for I in 1 .. 2 loop
                        Stream_Element'Read (Chan, Junk);
                        Len := Len * 256 + Natural (Junk);
                     end loop;
                  elsif Len = 127 then
                     Len := 0;
                     for I in 1 .. 8 loop
                        Stream_Element'Read (Chan, Junk);
                        Len := Len * 256 + Natural (Junk);
                     end loop;
                  end if;

                  if not Masked then
                     Wire.Note_Error
                       ("a client-to-server frame arrived unmasked");
                     exit;
                  end if;

                  for I in 1 .. 4 loop
                     Stream_Element'Read (Chan, Junk);
                     M := M * 256 + Mask_Value (Junk);
                  end loop;
                  Wire.Note_Mask (M);

                  for I in 1 .. Len loop
                     Stream_Element'Read (Chan, Junk);
                  end loop;
               end;
            end loop;
         exception
            when others =>
               null;   --  client went away; what was collected stands
         end;
         begin
            Close_Socket (Conn);
         exception
            when others => null;
         end;
      end loop;

      begin
         Close_Socket (Listener);
      exception
         when others => null;
      end;

      --  Terminate alternative: the main task returns early on some
      --  failure paths without calling Finished, and a bare accept
      --  would park this task with the master waiting on it.
      select
         accept Finished;
      or
         terminate;
      end select;
   exception
      when E : others =>
         Wire.Note_Error
           ("peer raised " & Ada.Exceptions.Exception_Name (E) & ": "
            & Ada.Exceptions.Exception_Message (E));
         select
            accept Finished;
         or
            terminate;
         end select;
   end Peer;

   Mask_Bytes  : constant := 4;    --  RFC 6455 5.3 masking key
   Nonce_Bytes : constant := 16;   --  4.1 Sec-WebSocket-Key nonce

   Draws_Before : Natural;
   Bytes_Before : Natural;
   Drew_During  : Natural;
   Bytes_During : Natural;
   Listening    : Boolean;

begin
   --  Case 1: what the client put on the wire.
   Draws_Before := AHT.Random.Draws;
   Bytes_Before := AHT.Random.Bytes_Requested;

   select
      Peer.Ready (Listening);
   or
      delay 10.0;
      Listening := False;
      Fail ("the fake peer never reported readiness");
   end select;

   if not Listening then
      Fail ("no peer to talk to: " & Wire.Error);
      Put_Line ("test_ws_masking:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;

   for C in 1 .. Connections loop
      declare
         Cl        : AHT.Websocket.Client.Client_Type;
         Connected : Boolean := False;
      begin
         AHT.Websocket.Client.Connect (Cl, URL);
         Connected := True;
         for F in 1 .. Frames_Each loop
            AHT.Websocket.Client.Send_Text (Cl, "mask me");
         end loop;
         --  Timeout 0.0: this peer never answers a Close, and the
         --  handshake is not what is under test here.
         AHT.Websocket.Client.Close (Cl, Timeout => 0.0);
         Connected := False;
      exception
         when E : others =>
            Fail ("connection" & Integer'Image (C) & " raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));

            --  A client that connected and then raised still owns a
            --  receiver parked on a socket this peer holds open, and
            --  leaving the scope waits for it, so the test would hang
            --  after announcing its failure. Bounded and best-effort:
            --  the aim is to release the receiver, not to complete a
            --  handshake.
            if Connected then
               begin
                  AHT.Websocket.Client.Close
                    (Cl, Timeout => 0.0, Drain_Timeout => 2.0);
               exception
                  when others => null;
               end;
            end if;
      end;
   end loop;

   select
      Peer.Finished;
   or
      delay 30.0;
      Fail ("the fake peer never finished");
   end select;
   Drew_During  := AHT.Random.Draws - Draws_Before;
   Bytes_During := AHT.Random.Bytes_Requested - Bytes_Before;

   if Wire.Error /= "" then
      Fail ("the peer reported: " & Wire.Error);
   end if;

   --  Nonces: one per connection, 16 bytes before base64. Over 128
   --  bits a legitimate repeat is impossible for any practical
   --  purpose, so a repeat here is the per-call generator reset this
   --  test exists to catch.
   if Wire.Nonce_Count < Connections then
      Fail ("only" & Natural'Image (Wire.Nonce_Count) & " of"
            & Natural'Image (Connections)
            & " handshakes were observed, so the nonce check would "
            & "prove nothing");
   else
      for I in 1 .. Wire.Nonce_Count loop
         for J in I + 1 .. Wire.Nonce_Count loop
            if Wire.Nonce_At (I) = Wire.Nonce_At (J) then
               Fail ("connections" & Integer'Image (I) & " and"
                     & Integer'Image (J)
                     & " sent the SAME Sec-WebSocket-Key ("
                     & Wire.Nonce_At (I)
                     & ") — the nonce is not drawn per connection "
                     & "from a strong source");
            end if;
         end loop;
      end loop;
   end if;

   --  Masks were observed at all, and are not a stuck constant. Not
   --  a duplicate check; see the header.
   if Wire.Mask_Count < Mask_Samples then
      Fail ("only" & Natural'Image (Wire.Mask_Count) & " of"
            & Natural'Image (Mask_Samples)
            & " frame masks were observed, so the checks would prove "
            & "nothing");
   else
      declare
         Same : Boolean := True;
      begin
         for I in 2 .. Wire.Mask_Count loop
            if Wire.Mask_At (I) /= Wire.Mask_At (1) then
               Same := False;
               exit;
            end if;
         end loop;
         if Same then
            Fail ("every one of" & Natural'Image (Wire.Mask_Count)
                  & " frames carried the same mask — the mask is a "
                  & "constant, which is the one thing masking must "
                  & "never be");
         end if;
      end;
   end if;

   --  The production paths requested entropy of the expected widths,
   --  one per frame and one per handshake. calls = masks + nonces and
   --  bytes = 4*masks + 16*nonces solve uniquely for the number of
   --  requests of each width, each checked against the wire count. A
   --  request is not attributed to a caller: a missing 4-byte request
   --  and an unrelated extra one still balance.
   declare
      Expected : constant Natural := Wire.Mask_Count + Connections;

      --  nonces = (bytes - 4*calls) / 12, from the pair above. Both
      --  inputs count REQUESTS, including any that failed, so the
      --  algebra is exact.
      Num       : constant Integer :=
        Integer (Bytes_During) - Mask_Bytes * Integer (Drew_During);
      Solvable  : constant Boolean :=
        Num >= 0 and then Num mod (Nonce_Bytes - Mask_Bytes) = 0;
      Nonces    : constant Integer :=
        (if Solvable then Num / (Nonce_Bytes - Mask_Bytes) else -1);
      Masks     : constant Integer :=
        (if Solvable then Integer (Drew_During) - Nonces else -1);
   begin
      if not Solvable then
         Fail ("the" & Natural'Image (Drew_During) & " draws totalling"
               & Natural'Image (Bytes_During)
               & " bytes cannot be accounted for as 4-byte masks and "
               & "16-byte nonces — something else is drawing from the "
               & "entropy source");
      else
         if Masks /= Integer (Wire.Mask_Count) then
            Fail (Integer'Image (Masks)
                  & " mask-width (4-byte) entropy requests were made "
                  & "while" & Natural'Image (Wire.Mask_Count)
                  & " masked frames went out — one request per frame "
                  & "was expected, so a request of that width is "
                  & "missing or surplus");
         end if;
         if Nonces /= Connections then
            Fail (Integer'Image (Nonces)
                  & " nonce-width (16-byte) entropy requests were made "
                  & "while" & Natural'Image (Connections)
                  & " handshakes went out — one request per handshake "
                  & "was expected, so a request of that width is "
                  & "missing or surplus");
         end if;
      end if;
      --  Exact, not a lower bound: the peer ignores parse errors, so
      --  its count can only be low, and a lower bound would let the
      --  surplus of mask draws pay for missing nonce draws.
      if Drew_During /= Expected then
         Fail (Natural'Image (Drew_During)
               & " entropy requests were made while"
               & Natural'Image (Wire.Mask_Count)
               & " masked frames and" & Natural'Image (Connections)
               & " handshakes went out — exactly"
               & Natural'Image (Expected)
               & " were expected. The request totals and the wire "
               & "observations disagree: either a request is missing "
               & "or surplus, or the peer did not observe every frame "
               & "that was sent");
      end if;
   end;

   --  Case 2: properties of the source itself.
   declare
      Value_Seen : array (AHT.Bytes.Octet) of Boolean := [others => False];
      Nonzero    : Boolean := False;
      Missing    : Natural := 0;
   begin
      for I in 1 .. 4096 loop
         declare
            B : AHT.Bytes.Byte_Array (1 .. 16);
         begin
            AHT.Random.Fill (B);
            for J in B'Range loop
               Value_Seen (B (J)) := True;
               if B (J) /= 0 then
                  Nonzero := True;
               end if;
            end loop;
         end;
      end loop;

      if not Nonzero then
         Fail ("every byte drawn was zero — the source produces "
               & "nothing");
      end if;
      for V in Value_Seen'Range loop
         if not Value_Seen (V) then
            Missing := Missing + 1;
         end if;
      end loop;
      if Missing > 0 then
         Fail (Natural'Image (Missing)
               & " of 256 byte values never appeared across 65536 "
               & "bytes — the source is confined to a sub-range");
      end if;
   exception
      when E : others =>
         Fail ("sampling the source raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end;

   if Failures = 0 then
      Put_Line ("test_ws_masking: OK ("
                & Natural'Image (Wire.Mask_Count)
                & " wire masks," & Natural'Image (Wire.Nonce_Count)
                & " nonces; matching entropy-request populations "
                & "observed)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_masking:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Masking;
