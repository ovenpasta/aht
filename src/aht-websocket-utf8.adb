--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package body AHT.Websocket.UTF8 is

   use type AHT.Bytes.Octet;

   --  Incremental RFC 3629 scanner. `Pending` counts continuation bytes
   --  still owed by the sequence in progress; `Lo .. Hi` is the range the
   --  *next* continuation byte must fall in. The first continuation of a
   --  3/4-byte sequence carries a tighter range than 80..BF so that
   --  overlong forms (E0 80.., F0 80..), surrogates (ED A0..) and values
   --  above U+10FFFF (F4 90..) are rejected at the second byte; after it,
   --  the range relaxes to 80..BF.
   type Scan is record
      Pending : Natural          := 0;
      Lo      : AHT.Bytes.Octet  := 16#80#;
      Hi      : AHT.Bytes.Octet  := 16#BF#;
      Failed  : Boolean          := False;
   end record;

   procedure Step (S : in out Scan; B : AHT.Bytes.Octet) is
   begin
      if S.Pending = 0 then
         case B is
            when 16#00# .. 16#7F# => null;                       -- ASCII
            when 16#C2# .. 16#DF# =>
               S.Pending := 1; S.Lo := 16#80#; S.Hi := 16#BF#;
            when 16#E0#           =>
               S.Pending := 2; S.Lo := 16#A0#; S.Hi := 16#BF#;
            when 16#E1# .. 16#EC# =>
               S.Pending := 2; S.Lo := 16#80#; S.Hi := 16#BF#;
            when 16#ED#           =>
               S.Pending := 2; S.Lo := 16#80#; S.Hi := 16#9F#;
            when 16#EE# .. 16#EF# =>
               S.Pending := 2; S.Lo := 16#80#; S.Hi := 16#BF#;
            when 16#F0#           =>
               S.Pending := 3; S.Lo := 16#90#; S.Hi := 16#BF#;
            when 16#F1# .. 16#F3# =>
               S.Pending := 3; S.Lo := 16#80#; S.Hi := 16#BF#;
            when 16#F4#           =>
               S.Pending := 3; S.Lo := 16#80#; S.Hi := 16#8F#;
            when others           =>
               --  C0, C1, a lone 80..BF, and F5..FF can never start a
               --  well-formed sequence.
               S.Failed := True;
         end case;
      elsif B < S.Lo or else B > S.Hi then
         S.Failed := True;
      else
         S.Pending := S.Pending - 1;
         S.Lo := 16#80#;
         S.Hi := 16#BF#;
      end if;
   end Step;

   function Is_Valid (Data : AHT.Bytes.Byte_Array) return Boolean is
      S : Scan;
   begin
      for B of Data loop
         Step (S, B);
         exit when S.Failed;
      end loop;
      return not S.Failed and then S.Pending = 0;
   end Is_Valid;

   function Is_Valid (Data : AHT.Bytes.Buffer) return Boolean is
      Result : Boolean := True;

      procedure Scan_View (View : AHT.Bytes.Byte_Array) is
      begin
         Result := Is_Valid (View);
      end Scan_View;
   begin
      Data.Query (Scan_View'Access);
      return Result;
   end Is_Valid;

end AHT.Websocket.UTF8;
