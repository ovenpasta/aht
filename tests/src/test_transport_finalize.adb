--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;

--  Exercises AHT.Transport.Transport_Type's inherited Finalize, which
--  dispatches to the concrete Close so an abandoned transport is still
--  reclaimed at scope exit. Uses an in-process test double, no socket
--  and no fixture, so both branches (Close runs / Close raises and is
--  swallowed) are driven deterministically.
procedure Test_Transport_Finalize is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_transport_finalize: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Observable side effects that outlive the finalized object: Close
   --  bumps the counter, and (when armed) raises so the test can check
   --  that Finalize swallows it.
   Close_Count    : Natural := 0;
   Raise_On_Close : Boolean := False;

   Probe_Error : exception;

   type Probe_Transport is new AHT.Transport.Transport_Type with null record;

   overriding procedure Write
     (Self : in out Probe_Transport; Data : AHT.Bytes.Byte_Array) is null;

   overriding procedure Read
     (Self : in out Probe_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);

   overriding procedure Close (Self : in out Probe_Transport);

   overriding function Is_Connected (Self : Probe_Transport) return Boolean
   is (False);

   overriding procedure Read
     (Self : in out Probe_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural) is
   begin
      Data := [others => 0];
      Last := 0;
   end Read;

   overriding procedure Close (Self : in out Probe_Transport) is
   begin
      Close_Count := Close_Count + 1;
      if Raise_On_Close then
         raise Probe_Error with "boom from Close";
      end if;
   end Close;

begin
   --  Case 1: a transport that leaves scope without an explicit Close is
   --  still reclaimed: Finalize dispatches to the concrete Close exactly
   --  once.
   Close_Count    := 0;
   Raise_On_Close := False;
   declare
      P : Probe_Transport;
   begin
      if P.Is_Connected then
         Fail ("probe reported connected before scope exit");
      end if;
   end;  --  P finalized here -> Close
   if Close_Count /= 1 then
      Fail ("scope exit did not dispatch Close once (Close_Count ="
            & Natural'Image (Close_Count) & ")");
   end if;

   --  Case 2: Finalize never propagates. A Close that raises must not
   --  let the exception escape the scope exit (a propagating Finalize
   --  would otherwise become Program_Error during unwinding).
   Close_Count    := 0;
   Raise_On_Close := True;
   begin
      declare
         P : Probe_Transport;
      begin
         if P.Is_Connected then
            Fail ("raising-probe reported connected before scope exit");
         end if;
      end;  --  Finalize -> Close raises -> swallowed
      if Close_Count /= 1 then
         Fail ("raising Close not invoked by Finalize (Close_Count ="
               & Natural'Image (Close_Count) & ")");
      end if;
   exception
      when others =>
         Fail ("Finalize let an exception escape from a raising Close");
   end;

   --  Case 3: an explicit Close followed by scope-exit Finalize drives
   --  Close twice, the contract Finalize relies on. A real transport's
   --  Close is idempotent; this confirms the second (Finalize) call
   --  still happens and is harmless.
   Close_Count    := 0;
   Raise_On_Close := False;
   declare
      P : Probe_Transport;
   begin
      P.Close;
   end;  --  Finalize -> Close again
   if Close_Count /= 2 then
      Fail ("explicit Close + Finalize did not call Close twice "
            & "(Close_Count =" & Natural'Image (Close_Count) & ")");
   end if;

   if Failures = 0 then
      Put_Line ("test_transport_finalize: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_transport_finalize:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Transport_Finalize;
