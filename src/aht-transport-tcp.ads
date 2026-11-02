--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Real_Time;
with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.URL;

private with GNAT.Sockets;

package AHT.Transport.TCP is

   type TCP_Transport is new Transport_Type with private;

   procedure Connect
     (Self            : in out TCP_Transport;
      Host            : String;
      Port            : AHT.URL.Port_Number;
      Connect_Timeout : Duration := Duration'Last;
      Resolve_Timeout : Duration := Duration'Last);
   --  Resolves Host via AHT.DNS (getaddrinfo, so IPv6 answers are
   --  used) and tries each address in resolver order; an IP literal
   --  skips the lookup. Resolve_Timeout bounds the lookup:
   --  Timeout_Error, distinct from the Transport_Error of a lookup
   --  with no usable address. Connect_Timeout is one total budget
   --  across all candidates: Timeout_Error. Duration'Last leaves
   --  either unbounded.
   --  Single-use: after a successful Connect every later Connect
   --  raises Transport_Error, even after Close, even when poisoned.
   --  A Connect that fails before a session leaves the object usable.

   type Endpoint is record
      Host : Ada.Strings.Unbounded.Unbounded_String;
      Port : AHT.URL.Port_Number := 1;
   end record;

   type Endpoint_List is array (Positive range <>) of Endpoint;

   procedure Connect_Candidates
     (Self            : in out TCP_Transport;
      Endpoints       : Endpoint_List;
      Connect_Timeout : Duration := Duration'Last)
     with Pre => Endpoints'Length > 0;
   --  Each Host must be a numeric IP literal; no DNS. Tries each
   --  endpoint in order; a Socket_Error closes that socket and moves
   --  on; first success wins. All failed for a non-timeout reason:
   --  Transport_Error with the last message. Connect_Timeout is one
   --  total budget across all candidates: Timeout_Error.
   --  Public so tests can drive the fallback with an explicit list;
   --  Connect delegates to this after DNS lookup.

   overriding procedure Write
     (Self : in out TCP_Transport;
      Data : AHT.Bytes.Byte_Array);

   overriding procedure Read
     (Self : in out TCP_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);
   --  Concurrency contract: at most one task in Read and one task in
   --  Write concurrently (the receiver-task-plus-sender shape). Each
   --  direction parks on its own single-waiter selector, so a second
   --  concurrent reader (or writer) is not supported.

   procedure Read
     (Self     : in out TCP_Transport;
      Data     : out AHT.Bytes.Byte_Array;
      Last     : out Natural;
      Deadline : Ada.Real_Time.Time);

   procedure Write
     (Self     : in out TCP_Transport;
      Data     : AHT.Bytes.Byte_Array;
      Deadline : Ada.Real_Time.Time);
   --  Bound one operation by an absolute instant; the compound
   --  Set_*_Deadline state is ignored for that call. Otherwise
   --  identical, including Abort_Pending and the write-poison rules.
   --  Time_Last means unbounded, as it does for the TLS handshake
   --  deadline that uses these overloads. Used by the TLS backends.

   overriding procedure Close (Self : in out TCP_Transport);
   --  Closes the socket and both selectors and clears the deadlines.
   --  Idempotent; safe on a clean or poisoned object.
   --  Precondition: no other task is inside any operation on this
   --  transport. Not enforced. GNAT forbids Close_Selector while a
   --  task is parked in Check_Selector, so a Close racing a reader
   --  can only best-effort the selector teardown. For the concurrent
   --  fatal-write case use Poison and defer Close until the reader
   --  has exited.

   type Try_Read_Status is (Would_Block, Data_Ready, Peer_Closed);

   procedure Try_Read
     (Self   : in out TCP_Transport;
      Data   : out AHT.Bytes.Byte_Array;
      Last   : out Natural;
      Status : out Try_Read_Status);
   --  One receive on the non-blocking socket, without parking on the
   --  selector: returns at once with Would_Block when nothing is
   --  queued, Data_Ready with Last the index of the last byte stored,
   --  or Peer_Closed on the stream's end. Last is 0 unless Data_Ready.
   --  Stores at most 16 KiB of a longer Data; the rest of
   --  the socket's queue waits for the next call. Ignores
   --  Set_Read_Deadline (there is no wait to bound) and is not
   --  interruptible by Abort_Pending. Empty Data: Would_Block.
   --  Occupies the reader role of the concurrency contract above.

   overriding function Is_Connected (Self : TCP_Transport) return Boolean;

   overriding procedure Set_Read_Deadline
     (Self     : in out TCP_Transport;
      Deadline : Duration);

   overriding procedure Set_Write_Deadline
     (Self     : in out TCP_Transport;
      Deadline : Duration);

   overriding procedure Abort_Pending (Self : in out TCP_Transport);
   --  Calls `Abort_Selector` on the persistent selector created in
   --  `Connect`, unblocking any `Read` or `Write` parked in
   --  `Check_Selector` and causing it to raise `Aborted_Error`. Safe
   --  cross-task.

   procedure Poison (Self : in out TCP_Transport);
   --  Marks a dead connection unusable after a fatal mid-stream error:
   --  Is_Connected becomes False, the socket is shut down, both
   --  selectors are aborted so a parked Read or Write wakes. Nothing
   --  is freed; that is Close's job. Safe while another task is
   --  parked in Read, Write or Abort_Pending on this transport.
   --  A Read or Write woken by this raises Transport_Error ("poisoned
   --  after its entry check"), not Aborted_Error and not EOF; the
   --  entry-guard message differs so a test can tell which check
   --  fired. A poisoned transport is single-use: Close it and use a
   --  fresh object.

private

   type TCP_Transport is new Transport_Type with record
      Socket             : GNAT.Sockets.Socket_Type := GNAT.Sockets.No_Socket;
      Selector           : GNAT.Sockets.Selector_Type;
      Write_Selector     : GNAT.Sockets.Selector_Type;
      --  Read and Write can run concurrently and one Selector_Type
      --  cannot hold two Check_Selector waiters, so each direction
      --  has its own. Abort_Pending aborts both. Created and closed
      --  together with Selector under Selector_Open.
      Selector_Open      : Boolean := False;
      Has_Deadline       : Boolean := False;
      Deadline_At        : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      Has_Write_Deadline : Boolean := False;
      Write_Deadline_At  : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      Connected          : Boolean := False with Atomic;
      --  Atomic: Poison clears it from one task while a reader
      --  parked in Check_Selector decides what its wake means by
      --  reading it. The other flags are written only by Connect
      --  and Close, which the lifecycle contract single-threads.
      Used               : Boolean := False;
      --  Latched True at the first successful Connect, never
      --  cleared, not even by Close. A failed Connect leaves it
      --  False so a fresh attempt can retry.
   end record;

end AHT.Transport.TCP;
