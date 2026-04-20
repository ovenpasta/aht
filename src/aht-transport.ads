with AHT.Bytes;

package AHT.Transport is

   pragma Preelaborate;

   type Transport_Type is abstract tagged limited null record;
   type Transport_Access is access all Transport_Type'Class;

   Transport_Error : exception;

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
   --  which signals a clean peer close).

   procedure Close (Self : in out Transport_Type) is abstract;

   function Is_Connected (Self : Transport_Type) return Boolean is abstract;

end AHT.Transport;
