with AHT.Bytes;

package AHT.Transport is

   pragma Preelaborate;

   type Transport_Type is abstract tagged limited null record;
   type Transport_Access is access all Transport_Type'Class;

   Transport_Error : exception;
   Timeout_Error   : exception;
   Aborted_Error   : exception;

   procedure Write
     (Self : in out Transport_Type;
      Data : AHT.Bytes.Byte_Array)
   is abstract;

   procedure Read
     (Self : in out Transport_Type;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is abstract;
   --  Blocking read: fills `Data` up to its bound or until peer closes;
   --  Last is the index of the last valid byte (0 if nothing was read,
   --  which signals a clean peer close). May raise `Timeout_Error` or
   --  `Aborted_Error` on implementations that support the hooks below.

   procedure Close (Self : in out Transport_Type) is abstract;

   function Is_Connected (Self : Transport_Type) return Boolean is abstract;

   --  Optional read-side deadline / cancel hooks. The default bodies
   --  are no-ops, so implementations that can't enforce them do
   --  nothing and Read blocks indefinitely.

   procedure Set_Read_Deadline
     (Self     : in out Transport_Type;
      Deadline : Duration) is null
     with Pre'Class => Deadline >= 0.0;
   --  Max time the next Read (and subsequent reads until reset) may
   --  block before raising `Timeout_Error`. `Duration'Last` means no
   --  deadline (the default initial state).

   procedure Abort_Pending (Self : in out Transport_Type) is null;
   --  Unblock a Read in progress (typically from another task) by
   --  causing it to raise `Aborted_Error`. Idempotent; safe to call
   --  when no read is pending.

end AHT.Transport;
