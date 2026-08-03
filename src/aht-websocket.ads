package AHT.Websocket is

   pragma Pure;

   type Opcode is
     (Continuation,  -- 0x0
      Text,          -- 0x1
      Binary,        -- 0x2
      Close_Op,      -- 0x8
      Ping_Op,       -- 0x9
      Pong_Op);      -- 0xA

   for Opcode use
     (Continuation => 16#0#,
      Text         => 16#1#,
      Binary       => 16#2#,
      Close_Op     => 16#8#,
      Ping_Op      => 16#9#,
      Pong_Op      => 16#A#);

   type Message_Kind is (Text_Message, Binary_Message);

   --  Close codes per RFC 6455 §7.4.
   --
   --  Any_Close_Code covers every value an endpoint might *observe*:
   --  the defined 1000..1015 range and the private 3000..4999 range.
   --  This is what the On_Close callback reports back to the user.
   subtype Any_Close_Code is Natural
     with Dynamic_Predicate =>
       Any_Close_Code in 1000 .. 1015
       or else Any_Close_Code in 3000 .. 4999;

   --  Valid_Close_Code excludes the codes an endpoint MUST NOT send on
   --  the wire (RFC 6455 §7.4.1):
   --    * 1004                    — reserved; no defined meaning, so it
   --                                must never be sent
   --    * 1005 "No Status Rcvd"   — local indication of absent status
   --    * 1006 "Abnormal Closure" — local indication of connection loss
   --    * 1015 "TLS handshake"    — local indication of TLS failure
   --  Used for the Code parameter of Close (i.e. outbound frames). A
   --  peer that sends any of these inbound is a protocol error handled
   --  by Frames.Classify_Inbound_Close (the Client replies 1002).
   subtype Valid_Close_Code is Any_Close_Code
     with Dynamic_Predicate =>
       Valid_Close_Code /= 1004
       and then Valid_Close_Code /= 1005
       and then Valid_Close_Code /= 1006
       and then Valid_Close_Code /= 1015;

   --  What the receiver task tells the On_Close callback about a close.
   --  The peer may send a Close frame without any status code at all
   --  (RFC 6455 §5.5.1); Has_Code = False represents that.
   type Close_Info (Has_Code : Boolean := False) is record
      case Has_Code is
         when True =>
            Code : Any_Close_Code;
         when False =>
            null;
      end case;
   end record;
   --  Reason (if any) is passed as a separate String argument by the
   --  callback signature, since an empty string is the normal "no
   --  reason" signal and does not need a discriminant.

   Handshake_Error : exception;
   Protocol_Error  : exception;
   Closed_Error    : exception;

   --  A frame or a reassembled message declares more bytes than the
   --  configured ceiling allows. Distinct from Protocol_Error because
   --  the peer did nothing malformed -- it asked for more than this
   --  endpoint is willing to hold -- and the two close the connection
   --  with different codes: 1009 Message Too Big rather than 1002.
   Message_Too_Big : exception;

   --  The operation is not available in the client's current
   --  configuration: Receive under Callback_Only delivery, connecting
   --  under Callback_Only with no callback installed, clearing that
   --  callback while such a connection is in force, or reconfiguring
   --  limits once a session already exists. All are the same mistake
   --  in different clothes -- asking for a delivery arrangement the
   --  client is not in a position to honour -- and none of them is a
   --  protocol fault, so none is a Protocol_Error.
   Mode_Error : exception;

end AHT.Websocket;
