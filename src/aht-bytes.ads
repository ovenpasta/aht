with Ada.Containers.Vectors;
with Interfaces;

package AHT.Bytes is

   pragma Preelaborate;

   use type Interfaces.Unsigned_8;

   subtype Octet is Interfaces.Unsigned_8;

   type Byte_Array is array (Positive range <>) of Octet;

   package Byte_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Positive,
      Element_Type => Octet);

   subtype Byte_Vector is Byte_Vectors.Vector;

   function From_String (S : String) return Byte_Array;
   function To_String   (B : Byte_Array) return String;

end AHT.Bytes;
