--  The masking key and the handshake nonce must be unpredictable.
--
--  RFC 6455 §5.3 requires the frame masking key to come from a strong
--  entropy source, and §4.1 requires Sec-WebSocket-Key to be a nonce
--  selected randomly per connection. Neither is about
--  confidentiality: masking exists so a client cannot be coerced into
--  emitting bytes a caching proxy would read as a second,
--  attacker-chosen HTTP request. A mask an observer can predict
--  defeats the purpose of masking entirely rather than weakening it,
--  and nothing about that is visible on the wire — which is why it
--  needs a test rather than a comment.
--
--  ---------------------------------------------------------------
--  What is tested, and where the samples come from
--  ---------------------------------------------------------------
--
--  Case 1 drives a real client against a fake peer that completes the
--  handshake and parses frames, and pairs two independent
--  observations: what the client emitted (masks and nonces, read off
--  the socket) and what it requested (entropy calls and their
--  widths, read from the counters).
--
--  Pairing them is the point. Sampling the entropy package alone
--  would pass with the production call sites reverted to a
--  clock-seeded generator, which is the defect being guarded; and
--  sampling the wire alone cannot tell a strong source from any
--  generator with plausible-looking output. Together they establish
--  that the expected populations of requests accompanied the frames
--  that went out.
--
--  What that does NOT establish is provenance — see the limit
--  section below.
--
--  Case 2 samples the source directly, for two properties a handful
--  of live frames cannot show: that the full byte range appears, and
--  that the output is not constant.
--
--  ---------------------------------------------------------------
--  Why the wiring is checked by COUNTING, not by sampling
--  ---------------------------------------------------------------
--
--  The obvious test — collect masks off the wire and look for
--  repeats — does not work, and it is worth writing down why so it is
--  not reinvented.
--
--  Duplicate-counting on 32-bit masks has no usable operating point.
--  At 4096 samples a legitimate collision happens with probability
--  0.195% per run, roughly one CI run in 512: a flake, not a finding.
--  Shrink the sample to make that negligible and the detection power
--  goes with it — the measured regression produced 4 collisions in
--  4096 draws, which scales to 0.016 at 256. Tried both: reverting
--  the production mask call to a per-call-reset generator left a
--  256-sample duplicate check completely green.
--
--  And no sample size fixes the general case. A PRNG seeded once and
--  drawn sequentially produces uniform, non-repeating output, so no
--  statistical test on the bytes can tell it from the OS pool.
--
--  What CAN be pinned deterministically is that the production paths
--  REQUEST the expected entropy. AHT.Random counts calls and bytes,
--  and because the two callers ask for different widths — 4 for a
--  mask, 16 for a nonce — those two totals form a solvable system and
--  the request populations can be recovered exactly and checked
--  against what the peer saw on the wire. That catches every reverted
--  call site, including the seeded-once PRNG no sampling would catch.
--
--  ---------------------------------------------------------------
--  The limit of that, stated precisely
--  ---------------------------------------------------------------
--
--  Counters establish that the entropy was requested. They do NOT
--  establish that those particular bytes became the mask or the
--  nonce. This substitution satisfies every count exactly and still
--  puts predictable bytes on the wire:
--
--      AHT.Random.Fill (Dummy);            --  right width, discarded
--      Fill_From_A_Predictable_PRNG (Key); --  what actually ships
--
--  Verified: it passes. So the honest claim is "the paths requested
--  the entropy they should have", not "these bytes are the entropy".
--
--  Closing it needs a provider that emits recognisable bytes, so the
--  wire value can be matched against what was handed out. That does
--  NOT require exposing substitution to library users: a test-only
--  alternate body, selected by this project's source directories,
--  would do it without adding anything to the public API.
--
--  It is rejected on cost, not on safety. Two bodies for one package
--  means the tested build is not the shipped build, which is a poor
--  trade for closing an adversarial construction — draw, discard,
--  use something else — that no refactor produces, when every
--  realistic regression (call removed, call swapped, source
--  replaced) is already caught. If the entropy path grows past two
--  call sites, that calculation is worth redoing.
--
--  The wire samples are still collected, for what they genuinely
--  show: that frames are masked at all, that the mask is not a
--  constant, and that nonces differ per connection.

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

   --  Eight connections of thirty-two frames each. The size is not a
   --  statistical threshold -- nothing here counts duplicates any
   --  more -- it just needs to be large enough that a mask stuck at a
   --  constant is obvious, and spread over several connections so the
   --  nonce is sampled per connection rather than once.
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

   ---------------------------------------------------------------
   --  Handshake helpers (the same computation the client does)
   ---------------------------------------------------------------

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

   ---------------------------------------------------------------
   --  The fake peer
   ---------------------------------------------------------------

   --  Ready carries a status rather than being a bare rendezvous.
   --
   --  It used to be bare, and that deadlocked: if the bind failed --
   --  the port already in use, say -- the peer raised before ever
   --  reaching `accept Ready`, so the main task waited on Ready
   --  forever while the peer waited on Finished forever. A test that
   --  hangs on a busy port is worse than one that fails on it. Both
   --  entries are now on every path, and the main task's calls are
   --  timed so that a peer which dies in some way not foreseen here
   --  still produces a report rather than a wedge.
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

      --  Accepted whether or not the socket came up, and with a
      --  terminate alternative: the main task's call is timed, so if
      --  it expires while this task is merely slow, nobody will ever
      --  call Ready again and a bare accept would park here forever
      --  -- with master finalization then waiting on this task. Every
      --  accept in this task needs the alternative for that reason,
      --  not just the last one.
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
            --  4-byte mask off each. Every client-to-server frame
            --  must be masked (§5.3), so an unmasked one is itself a
            --  finding.
            --
            --  Every frame, not a fixed count: the client also sends
            --  a Close frame, which draws a mask like any other. A
            --  peer that stopped at Frames_Each would undercount, and
            --  the draw check below -- which is calibrated from this
            --  number -- would then have exactly enough slack to hide
            --  a missing nonce draw. It did, before this was fixed.
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

      --  A terminate alternative, not a bare accept.
      --
      --  The main task returns early on some failure paths without
      --  ever reaching Peer.Finished, and a bare accept would then
      --  park this task forever -- so the test printed its diagnosis
      --  and the PROCESS still hung, because Ada waits for dependent
      --  tasks before leaving the master. `terminate` lets the task
      --  end when the master is finishing and no call can arrive.
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

   Mask_Bytes  : constant := 4;    --  RFC 6455 §5.3 masking key
   Nonce_Bytes : constant := 16;   --  §4.1 Sec-WebSocket-Key nonce

   Draws_Before : Natural;
   Bytes_Before : Natural;
   Drew_During  : Natural;
   Bytes_During : Natural;
   Listening    : Boolean;

begin
   ---------------------------------------------------------------
   --  Case 1: what the client actually put on the wire.
   ---------------------------------------------------------------
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

            --  Reporting is not enough. A client that connected and
            --  then raised still owns a receiver parked on a socket
            --  this peer holds open, and leaving the scope waits for
            --  it -- so the test would hang after announcing its
            --  failure, which is the worst of both. Bounded and
            --  best-effort: the aim is to release the receiver, not
            --  to complete a handshake.
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

   --  Masks were observed at all, and are not a stuck constant.
   --  Deliberately NOT a duplicate check -- see the header.
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

   --  The deterministic check: the production paths requested entropy
   --  of the expected widths, one per frame and one per handshake.
   --  Reverting either call site to another generator leaves the
   --  corresponding population short, however good that generator's
   --  output looks.
   --
   --  Split by WIDTH, not by caller. Counting calls alone cannot
   --  separate requests of different sizes, so a missing call and a
   --  compensating extra call cancel. Counting bytes as well removes
   --  that, because the two callers ask for different widths:
   --
   --      calls =      masks +       nonces
   --      bytes =  4 * masks +  16 * nonces
   --
   --  is two equations in two unknowns and solves uniquely for how
   --  many requests of each width were made. Each population is then
   --  checked against what was independently observed on the wire, so
   --  a shortfall in one width cannot be paid for by a surplus in the
   --  other.
   --
   --  It does not attribute a request to a caller. Two 4-byte
   --  requests are indistinguishable, so a missing one and an
   --  unrelated extra one still balance.
   declare
      Expected : constant Natural := Wire.Mask_Count + Connections;

      --  nonces = (bytes - 4*calls) / 12, from the pair above. Both
      --  inputs count REQUESTS, including any that failed, which is
      --  what makes the algebra exact rather than best-effort.
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
      --  Exact, not a lower bound.
      --
      --  A lower bound lets one deficit be paid for by another
      --  surplus. That is not hypothetical: with the peer counting
      --  only Frames_Each frames it missed each connection's Close
      --  frame, whose own mask draw then covered the eight missing
      --  nonce draws exactly, and reverting the nonce path passed.
      --  Requiring equality means a swallowed parse error -- the peer
      --  ignores them, so its count can only ever be low -- shows up
      --  as a surplus of draws rather than silently financing a
      --  missing one.
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

   ---------------------------------------------------------------
   --  Case 2: properties of the source itself.
   ---------------------------------------------------------------
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
