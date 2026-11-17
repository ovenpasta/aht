--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Strings.Unbounded;

with AHT.Transport;
with AHT.URL;

private with Ada.Containers.Vectors;
private with Ada.Finalization;
private with Ada.Real_Time;
private with AHT.Transport.TCP;
private with AHT.Transport.TLS;

--  Idle HTTP/1.1 connections kept open for reuse (keep-alive).
--
--  A pool is reached through Pool_Ref, a counted handle: copies share
--  one pool, and the last copy to go closes every idle connection.
--  AHT.HTTP.Client uses a pool when its Pool field holds one; that
--  is the whole of the user-facing surface. The connection operations
--  below are public so the pool can be driven on its own, by a test
--  or by another transport owner.
package AHT.HTTP.Connection_Pools is

   type Pool_Ref is private;
   --  Default: no pool.

   function Create
     (Max_Idle_Per_Host : Positive := 4;
      Max_Idle          : Positive := 32;
      Idle_Timeout      : Duration := 30.0) return Pool_Ref
     with Pre => Idle_Timeout > 0.0;
   --  A new, empty pool. At most Max_Idle_Per_Host idle connections
   --  are kept per endpoint and Max_Idle in all; a release past either
   --  limit closes the endpoint's (or the pool's) longest-idle
   --  connection. A connection idle for Idle_Timeout seconds is
   --  closed instead of handed out, on the next Acquire or Release.

   function Is_Null (Self : Pool_Ref) return Boolean;
   --  True for a Pool_Ref that holds no pool.

   function Idle_Count (Self : Pool_Ref) return Natural
     with Pre => not Is_Null (Self);
   --  Connections idle in the pool now, expired ones included until
   --  the next Acquire or Release closes them.

   procedure Clear (Self : Pool_Ref)
     with Pre => not Is_Null (Self);
   --  Closes every idle connection. Connections out on loan are not
   --  affected and may be released afterwards.

   --  What a connection may be reused for: the same scheme, host
   --  (compared case-insensitively) and port, and for https the same
   --  trust settings, which the owner encodes in TLS_Profile.
   type Endpoint is record
      Scheme      : AHT.URL.Scheme_Kind := AHT.URL.HTTP;
      Host        : Ada.Strings.Unbounded.Unbounded_String;
      Port        : AHT.URL.Port_Number := 80;
      TLS_Profile : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   --  One connection, owned by whoever holds it: dialled by the
   --  holder, released to a pool or discarded. Not copyable in
   --  spirit: after Release or Discard the holder's object is empty.
   --  Acquire and Release take the holder's object by access so the
   --  pool can move ownership in one abort-deferred step: at every
   --  instant the transport belongs to the pool or to that object,
   --  never both and never neither.
   type Connection is private;

   function Is_Empty (C : Connection) return Boolean;

   function Transport (C : Connection) return AHT.Transport.Transport_Access
     with Pre => not Is_Empty (C);
   --  The connection's transport, for Connect and for the exchange.

   procedure Allocate (C : out Connection; Scheme : AHT.URL.Scheme_Kind)
     with Pre  => Scheme in AHT.URL.HTTP | AHT.URL.HTTPS,
          Post => not Is_Empty (C);
   --  A fresh, unconnected TCP (http) or TLS (https) transport. The
   --  allocation is abort-deferred (see AHT.Guarded_New).

   procedure Discard (C : in out Connection)
     with Post => Is_Empty (C);
   --  Closes and frees the transport. A no-op on an empty Connection.

   procedure Acquire
     (Self  : Pool_Ref;
      Where : Endpoint;
      C     : not null access Connection;
      Found : out Boolean)
     with Pre => not Is_Null (Self) and then Is_Empty (C.all);
   --  An idle connection for Where, the most recently released one,
   --  into C.all, or Found = False and C.all left empty. Expired idle connections are
   --  closed on the way. The caller checks the connection is still
   --  usable (AHT.Transport.Peer_Quiet) before writing to it.

   procedure Release
     (Self  : Pool_Ref;
      Where : Endpoint;
      C     : not null access Connection)
     with Pre  => not Is_Null (Self) and then not Is_Empty (C.all),
          Post => Is_Empty (C.all);
   --  Parks C.all as idle for Where, closing whatever the limits push
   --  out. Precondition, not checked: the connection sits at a message
   --  boundary with no Abort_Pending outstanding. Deadlines armed on
   --  it are the next user's to reset.

private

   type TCP_Access is access AHT.Transport.TCP.TCP_Transport;
   type TLS_Access is access AHT.Transport.TLS.TLS_Transport;

   type Connection is record
      TCP : TCP_Access;
      TLS : TLS_Access;
      --  At most one is set; the pool-specific pointers are what the
      --  transport is freed through.
   end record;

   type Idle_Entry is record
      Where : Endpoint;
      Conn  : Connection;
      Since : Ada.Real_Time.Time;
   end record;

   package Entry_Vectors is new Ada.Containers.Vectors
     (Index_Type => Positive, Element_Type => Idle_Entry);

   package Connection_Vectors is new Ada.Containers.Vectors
     (Index_Type => Positive, Element_Type => Connection);

   --  Bookkeeping only: every operation is list surgery under the
   --  lock. Connections pushed out (expired, over a limit) move to
   --  Doomed, still owned by the pool, and are popped one at a time
   --  into a controlled holder that closes them outside the protected
   --  action.
   protected type Pool_State
     (Max_Per_Host : Positive;
      Max_Total    : Positive)
   is
      procedure Set_Timeout (Timeout : Duration);

      procedure Take
        (Where : Endpoint;
         C     : not null access Connection;
         Found : out Boolean);

      procedure Put
        (Where : Endpoint;
         C     : not null access Connection);
      --  C.all is emptied in the same action that stores it.

      procedure Doom_All;

      procedure Pop_Doomed
        (C   : not null access Connection;
         Got : out Boolean);

      function Count return Natural;

      procedure Retain;
      procedure Release_Ref (Last : out Boolean);

   private
      Idle    : Entry_Vectors.Vector;
      Doomed  : Connection_Vectors.Vector;
      Timeout : Ada.Real_Time.Time_Span := Ada.Real_Time.Time_Span_Zero;
      Refs    : Natural := 1;
   end Pool_State;

   type Pool_State_Access is access Pool_State;

   type Pool_Ref is new Ada.Finalization.Controlled with record
      State : Pool_State_Access;
   end record;

   overriding procedure Adjust   (Self : in out Pool_Ref);
   overriding procedure Finalize (Self : in out Pool_Ref);

end AHT.HTTP.Connection_Pools;
