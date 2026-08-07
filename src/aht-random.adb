with AHT.Random.Source;

package body AHT.Random is

   --  Counting lives here, not in the platform bodies, so the two
   --  cannot drift: Draws and Bytes_Requested mean exactly the same
   --  thing on every target, and a new platform gets them for free by
   --  implementing one procedure.
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

      --  Counted on entry, before the attempt: a Fill that goes on to
      --  raise still increments both. "Did this path ask?" is the
      --  useful reading for the callers, and counting on success
      --  would report nothing at all for the failure case, which is
      --  when one most wants to know.
      Counter.Note (B'Length);

      Source.Get (B);
   end Fill;

end AHT.Random;
