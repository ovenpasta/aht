--  Copyright (C) 1999-2019 Gautier de Montmollin
--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: MIT

--  Huffman decoding tables for AHT.Inflate: multi-level lookup tables
--  built from a list of code lengths, as in info-zip's inflate.
--
--  Derived from UnZip.Decompress.Huffman in Zip-Ada 62
--  (https://unzip-ada.sourceforge.io), MIT licensed. The table layout
--  and the construction algorithm are Zip-Ada's; the tracing is gone,
--  and the table list is owned by a controlled holder so a decode that
--  unwinds (corrupt input, a transport exception raised by the input
--  callback, an abort) frees what it built.

with Ada.Finalization;

private package AHT.Inflate.Huffman is

   Invalid : constant := 99;

   type HufT_Table;
   type HufT_Table_Access is access HufT_Table;

   --  One lookup entry. Extra_Bits encodes the entry's kind:
   --    0 .. 13  a length or distance base N with that many extra bits
   --    15       end of block
   --    16       a literal byte N
   --    > 16     a link: Next_Table is indexed by Extra_Bits - 16 more
   --             bits
   --    Invalid  no code maps here
   --  Bits is how many input bits this entry consumes.
   type HufT is record
      Extra_Bits : Natural := Invalid;
      Bits       : Natural := 0;
      N          : Natural := 0;
      Next_Table : HufT_Table_Access;
   end record;

   type HufT_Table is array (Natural range <>) of HufT;

   type Table_Node;
   type Table_Node_Access is access Table_Node;

   type Table_Node is record
      Table : HufT_Table_Access;
      Next  : Table_Node_Access;
   end record;

   --  Owns every table of one code set; the first node's table is the
   --  root lookup table. Finalize frees the list.
   type Table_List is new Ada.Finalization.Limited_Controlled with record
      Head : Table_Node_Access;
   end record;

   overriding procedure Finalize (Self : in out Table_List);

   procedure Free (Self : in out Table_List);
   --  Frees every table now; Self.Head becomes null. Idempotent.

   type Length_Array is array (Integer range <>) of Natural;

   Empty : constant Length_Array (1 .. 0) := [others => 0];

   procedure Build
     (B          : Length_Array;
      S          : Integer;
      D, E       : Length_Array;
      Tables     : in out Table_List;
      M          : in out Integer;
      Incomplete : out Boolean);
   --  Builds the tables for the code lengths B into Tables, which must
   --  be empty. Symbols below S are literals (or end of block, 256);
   --  symbol S + K maps to base D (K) with E (K) extra bits. M is the
   --  root table's index width on entry and is clamped to the code
   --  lengths actually used. Incomplete is True when the lengths leave
   --  codes unassigned. Raises Huffman_Error on an oversubscribed or
   --  otherwise impossible set, with Tables left empty.

   Huffman_Error : exception;

end AHT.Inflate.Huffman;
