--  Copyright (C) 1999-2019 Gautier de Montmollin
--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: MIT

with Ada.Unchecked_Deallocation;
with Interfaces;

package body AHT.Inflate.Huffman is

   procedure Dispose is new
     Ada.Unchecked_Deallocation (HufT_Table, HufT_Table_Access);
   procedure Dispose is new
     Ada.Unchecked_Deallocation (Table_Node, Table_Node_Access);

   procedure Free (Self : in out Table_List) is
      Current : Table_Node_Access;
   begin
      while Self.Head /= null loop
         Dispose (Self.Head.Table);
         Current   := Self.Head;
         Self.Head := Self.Head.Next;
         Dispose (Current);
      end loop;
   end Free;

   overriding procedure Finalize (Self : in out Table_List) is
   begin
      Free (Self);
   end Finalize;

   procedure Build
     (B          : Length_Array;
      S          : Integer;
      D, E       : Length_Array;
      Tables     : in out Table_List;
      M          : in out Integer;
      Incomplete : out Boolean)
   is
      use Interfaces;

      B_Max   : constant := 16;
      B_Maxp1 : constant := B_Max + 1;

      --  Bit length count table.
      Count : array (0 .. B_Maxp1) of Integer := [others => 0];

      F   : Integer;   --  I repeats in the table every F entries
      G   : Integer;   --  maximum code length
      I   : Integer;   --  counter, current code
      J   : Integer;   --  counter
      Kcc : Integer;   --  number of bits in the current code

      C_Idx, V_Idx : Natural;

      Current_Table : HufT_Table_Access;
      Current_Node  : Table_Node_Access;
      New_Node      : Table_Node_Access;

      New_Entry : HufT;

      U : array (0 .. B_Max) of HufT_Table_Access;   --  table stack

      N_Max : constant := 288;
      --  Values in order of bit length.
      V : array (0 .. N_Max) of Integer := [others => 0];
      El_V, El_V_M_S : Integer;

      W : Natural := 0;   --  bits before this table

      Offset, Code_Stack : array (0 .. B_Maxp1) of Integer :=
        [others => 0];

      Table_Level : Integer := -1;
      Bits : array (Integer'(-1) .. B_Maxp1) of Integer := [others => 0];
      --  Bits (L) is the index width of the table at level L.

      Y  : Integer;       --  number of dummy codes added
      Z  : Natural := 0;  --  number of entries in the current table
      El : Integer;       --  length of the end-of-block code (256)

      No_Copy_Length_Array : constant Boolean :=
        D'Length = 0 or else E'Length = 0;
   begin
      Incomplete := False;

      if B'Length > 256 then
         El := B (B'First + 256);
      else
         El := B_Max;
      end if;

      --  Generate counts for each bit length.
      for K in B'Range loop
         if B (K) > B_Max then
            raise Huffman_Error;
         end if;
         Count (B (K)) := Count (B (K)) + 1;
      end loop;

      if Count (0) = B'Length then
         --  No codes at all: a complete, empty set.
         M := 0;
         return;
      end if;

      --  Find the minimum and maximum length, bound M by those.
      J := 1;
      while J <= B_Max and then Count (J) = 0 loop
         J := J + 1;
      end loop;
      Kcc := J;
      if M < J then
         M := J;
      end if;
      I := B_Max;
      while I > 0 and then Count (I) = 0 loop
         I := I - 1;
      end loop;
      G := I;
      if M > I then
         M := I;
      end if;

      --  Adjust the last length count to fill out codes, if needed.
      Y := Integer (Shift_Left (Unsigned_32'(1), J));
      while J < I loop
         Y := Y - Count (J);
         if Y < 0 then
            raise Huffman_Error;
         end if;
         Y := Y * 2;
         J := J + 1;
      end loop;

      Y := Y - Count (I);
      if Y < 0 then
         raise Huffman_Error;
      end if;
      Count (I) := Count (I) + Y;

      --  Starting offsets into the value table for each length.
      Offset (1) := 0;
      J := 0;
      for Idx in 2 .. I loop
         J := J + Count (Idx - 1);
         Offset (Idx) := J;
      end loop;

      --  Table of values in order of bit length.
      for Idx in B'Range loop
         J := B (Idx);
         if J /= 0 then
            V (Offset (J)) := Idx - B'First;
            Offset (J) := Offset (J) + 1;
         end if;
      end loop;

      --  Generate the codes and, for each, the table entries.
      Code_Stack (0) := 0;
      I := 0;
      V_Idx := V'First;
      Bits (-1) := 0;

      for K in Kcc .. G loop
         for Am1 in reverse 0 .. Count (K) - 1 loop
            --  I is the Huffman code of length K bits for V (V_Idx).
            while K > W + Bits (Table_Level) loop
               W := W + Bits (Table_Level);
               Table_Level := Table_Level + 1;
               Z := G - W;
               if Z > M then
                  Z := M;
               end if;
               J := K - W;
               F := Integer (Shift_Left (Unsigned_32'(1), J));
               if F > Am1 + 2 then
                  F := F - (Am1 + 2);
                  C_Idx := K;
                  loop
                     J := J + 1;
                     exit when J >= Z;
                     F := F * 2;
                     C_Idx := C_Idx + 1;
                     exit when F - Count (C_Idx) <= 0;
                     F := F - Count (C_Idx);
                  end loop;
               end if;

               if W + J > El and then W < El then
                  J := El - W;   --  make the EOB code end at a table
               end if;
               if W = 0 then
                  J := M;        --  the root table is always M bits
               end if;
               Z := Integer (Shift_Left (Unsigned_32'(1), J));
               Bits (Table_Level) := J;

               --  Allocate and link the new table.
               Current_Table := new HufT_Table (0 .. Z);
               New_Node := new Table_Node'(Current_Table, null);
               if Current_Node = null then
                  Tables.Head := New_Node;
               else
                  Current_Node.Next := New_Node;
               end if;
               Current_Node := New_Node;

               U (Table_Level) := Current_Table;

               --  Connect to the previous level's table, if any.
               if Table_Level > 0 then
                  Code_Stack (Table_Level) := I;
                  New_Entry.Bits       := Bits (Table_Level - 1);
                  New_Entry.Extra_Bits := 16 + J;
                  New_Entry.Next_Table := Current_Table;

                  J := Integer
                    (Shift_Right
                       (Unsigned_32 (I)
                        and (Shift_Left (Unsigned_32'(1), W) - 1),
                        W - Bits (Table_Level - 1)));

                  if J > U (Table_Level - 1)'Last then
                     raise Huffman_Error;
                  end if;
                  U (Table_Level - 1) (J) := New_Entry;
               end if;
            end loop;

            --  Set up the table entry in New_Entry.
            New_Entry.Bits       := K - W;
            New_Entry.Next_Table := null;

            if V_Idx >= B'Length then
               New_Entry.Extra_Bits := Invalid;
            else
               El_V := V (V_Idx);
               El_V_M_S := El_V - S;
               if El_V_M_S < 0 then
                  --  Simple code, raw value.
                  if El_V < 256 then
                     New_Entry.Extra_Bits := 16;
                  else
                     New_Entry.Extra_Bits := 15;
                  end if;
                  New_Entry.N := El_V;
               else
                  if No_Copy_Length_Array
                    or else El_V_M_S > E'Last - E'First
                  then
                     raise Huffman_Error;
                  end if;
                  New_Entry.Extra_Bits := E (E'First + El_V_M_S);
                  New_Entry.N          := D (D'First + El_V_M_S);
               end if;
               V_Idx := V_Idx + 1;
            end if;

            --  Fill code-like entries with New_Entry.
            F := Integer (Shift_Left (Unsigned_32'(1), K - W));
            J := Integer (Shift_Right (Unsigned_32 (I), W));
            while J < Z loop
               Current_Table (J) := New_Entry;
               J := J + F;
            end loop;

            --  Backwards increment the K-bit code I.
            J := Integer (Shift_Left (Unsigned_32'(1), K - 1));
            while (Unsigned_32 (I) and Unsigned_32 (J)) /= 0 loop
               I := Integer (Unsigned_32 (I) xor Unsigned_32 (J));
               J := J / 2;
            end loop;
            I := Integer (Unsigned_32 (I) xor Unsigned_32 (J));

            --  Back up over finished tables.
            while Integer (Unsigned_32 (I) and (Shift_Left (1, W) - 1))
              /= Code_Stack (Table_Level)
            loop
               Table_Level := Table_Level - 1;
               W := W - Bits (Table_Level);
            end loop;
         end loop;
      end loop;

      Incomplete := Y /= 0 and then G /= 1;
   exception
      when others =>
         Free (Tables);
         raise Huffman_Error;
   end Build;

end AHT.Inflate.Huffman;
