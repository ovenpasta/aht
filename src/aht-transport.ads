--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Finalization;

with AHT.Bytes;

package AHT.Transport is

   pragma Preelaborate;

   type Transport_Type is
     abstract new Ada.Finalization.Limited_Controlled with null record;
   type Transport_Access is access all Transport_Type'Class;

   Transport_Error : exception;
   Timeout_Error   : exception;
   Aborted_Error   : exception;

   procedure Write
     (Self : in out Transport_Type;
      Data : AHT.Bytes.Byte_Array)
   is abstract;
   --  Sends every byte of Data or raises. May raise Timeout_Error or
   --  Aborted_Error where Set_Write_Deadline / Abort_Pending are
   --  supported. Any of those, or Transport_Error, can be raised
   --  after some bytes reached the peer: a failed write is not
   --  all-or-nothing on the wire and is retry-unsafe for anything
   --  non-idempotent. An implementation that can desynchronise the
   --  stream must mark the connection dead (see TCP's Poison). The
   --  caller decides whether to retry.

   procedure Read
     (Self : in out Transport_Type;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is abstract;
   --  Blocking read: fills Data up to its bound or until the peer
   --  closes; Last is the index of the last valid byte, 0 on a clean
   --  peer close. May raise Timeout_Error or Aborted_Error where the
   --  hooks below are supported.
   --  Concurrency (all implementations): at most one task in Read and
   --  one task in Write at a time. Two concurrent readers, or two
   --  concurrent writers, are not supported.

   procedure Close (Self : in out Transport_Type) is abstract;

   function Is_Connected (Self : Transport_Type) return Boolean is abstract;

   --  Optional read-side deadline / cancel hooks. The default bodies
   --  are no-ops, so implementations that can't enforce them do
   --  nothing and Read blocks indefinitely.

   procedure Set_Read_Deadline
     (Self     : in out Transport_Type;
      Deadline : Duration) is null
     with Pre'Class => Deadline >= 0.0;
   --  Wall-clock budget, measured from this call, for every subsequent
   --  Read until reset. When it elapses, a Read in progress or started
   --  afterwards raises Timeout_Error. Compound: not refreshed per
   --  Read, so a peer dribbling one byte every Deadline / N seconds
   --  still trips it on call N+1. Duration'Last clears it (the initial
   --  state).

   procedure Set_Write_Deadline
     (Self     : in out Transport_Type;
      Deadline : Duration) is null
     with Pre'Class => Deadline >= 0.0;
   --  Write-side parallel of Set_Read_Deadline: a compound budget,
   --  measured from this call, for every subsequent Write until reset;
   --  when it elapses a Write in progress or started afterwards raises
   --  Timeout_Error. Duration'Last clears it.

   procedure Abort_Pending (Self : in out Transport_Type) is null;
   --  Unblock a Read or Write in progress (typically from another task)
   --  by causing it to raise `Aborted_Error`. Idempotent; safe to call
   --  when nothing is pending.

   overriding procedure Finalize (Self : in out Transport_Type);
   --  Dispatches to the concrete Close so an abandoned transport still
   --  drops its socket or TLS contexts. Never raises: exceptions from
   --  Close are swallowed, since Finalize runs during unwinding.
   --  Relies on every Close being idempotent.
   --  TLS overrides Finalize with abortive cleanup (no close_notify
   --  network write); explicit TLS Close retains graceful semantics.
   --  Inherits Close's precondition: no other task is inside any
   --  operation on this transport while it runs. The owners in this
   --  library satisfy it by structure: a standalone transport is used
   --  by one task; the WebSocket receiver closes its session after
   --  quiescing it, so Finalize runs on an already-closed transport.

end AHT.Transport;
