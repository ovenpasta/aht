--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with AHT.Random.Source;

package body AHT.Random is

   --  Counting lives here rather than in the platform bodies, so Draws
   --  and Bytes_Requested mean the same thing on every target.
   protected Counter is
      procedure Note (Bytes : Natural);
      function  Total return Natural;
      function  Total_Bytes return Natural;
   private
      N : Natural := 0;
      B : Natural := 0;
   end Counter;

   protected body Counter is
      procedure Note (Bytes : Natural) is
      begin
         if N < Natural'Last then
            N := N + 1;
         end if;
         if B <= Natural'Last - Bytes then
            B := B + Bytes;
         else
            B := Natural'Last;
         end if;
      end Note;

      function Total return Natural is (N);
      function Total_Bytes return Natural is (B);
   end Counter;

   function Draws return Natural is (Counter.Total);
   function Bytes_Requested return Natural is (Counter.Total_Bytes);

   ----------
   -- Fill --
   ----------

   procedure Fill (B : out AHT.Bytes.Byte_Array) is
   begin
      --  Handled here so no platform body has to, and so a null range
      --  is not counted as a request.
      if B'Length = 0 then
         return;
      end if;

      --  Counted on entry, before the attempt, so a Fill that goes on
      --  to raise still increments both.
      Counter.Note (B'Length);

      Source.Get (B);
   end Fill;

end AHT.Random;
