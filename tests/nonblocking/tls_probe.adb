--  Copyright (C) 2026 Zack Boll
--  SPDX-License-Identifier: Apache-2.0

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time;
with Ada.Text_IO;
with Interfaces.C;
with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

--  A low-level qualification probe, NOT a production WSS transport. Commands
--  come from the test driver on stdin; no Ada receiver task is created.
procedure TLS_Probe is
   use Ada.Text_IO;
   use type Ada.Real_Time.Time;
   use type Interfaces.C.int;
   Wire : AHT.Transport.TLS.TLS_Transport;
   Data : AHT.Bytes.Byte_Array (1 .. 4_096);
   Last : Natural;
   Port : constant AHT.URL.Port_Number :=
     AHT.URL.Port_Number'Value (Ada.Command_Line.Argument (2));

   function Fill_Send_Buffer (Peer_Port : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "task108_backpressure";

   function Available (Peer_Port : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "task108_available";

   procedure Emit (Message : String) is
   begin
      Put_Line (Message);
      Flush;
   end Emit;
begin
   begin
      Wire.Connect
        (Host => Ada.Command_Line.Argument (1), Port => Port,
         CA_Path => Ada.Command_Line.Argument (3),
         Resolve_Timeout => 0.5, Connect_Timeout => 0.5,
         Handshake_Deadline => 0.5);
      Emit ("CONNECTED");
   exception
      when E : others =>
         Emit ("CONNECT_ERROR " & Ada.Exceptions.Exception_Name (E) & " "
               & Ada.Exceptions.Exception_Message (E));
         Wire.Close;
         return;
   end;

   loop
      declare
         Command : constant String := Get_Line;
         Start : Ada.Real_Time.Time;
      begin
         if Command = "abort" or else Command = "abort-stay" then
            Start := Ada.Real_Time.Clock;
            Wire.Abortive_Close;
            Wire.Abortive_Close;
            Wire.Close;
            Emit ("ABORTED " & Duration'Image
              (Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Start))
              & " connected=" & Boolean'Image (Wire.Is_Connected));
            exit when Command = "abort";
         elsif Command = "finalize" then
            Emit ("FINALIZING");
            return;
         elsif Command = "expired" then
            Wire.Set_Read_Deadline (0.0);
            Wire.Set_Write_Deadline (0.0);
            Emit ("EXPIRED");
         elsif Command = "empty" then
            declare
               Empty : AHT.Bytes.Byte_Array (1 .. 0);
               Status : AHT.Transport.TLS.Read_Status;
               use type AHT.Transport.TLS.Read_Status;
            begin
               Wire.Try_Read (Empty, Last, Status);
               pragma Assert (Last = 0 and then Status = AHT.Transport.TLS.Idle);
               Emit ("EMPTY_IDLE");
            end;
         elsif Command = "shifted" then
            declare
               Shifted : AHT.Bytes.Byte_Array (7 .. 7) := [others => 0];
               Status : AHT.Transport.TLS.Read_Status;
               use type AHT.Transport.TLS.Read_Status;
            begin
               Wire.Try_Read (Shifted, Last, Status);
               Emit ("SHIFTED " & AHT.Transport.TLS.Read_Status'Image (Status)
                 & Natural'Image (Last) & Natural'Image
                   (if Status = AHT.Transport.TLS.Data_Ready
                    then Natural (Shifted (7)) else 0));
            end;
         elsif Command = "try" then
            Start := Ada.Real_Time.Clock;
            declare
               Status : AHT.Transport.TLS.Read_Status;
               Sum : Natural := 0;
            begin
               Wire.Try_Read (Data, Last, Status);
               for I in Data'First .. Last loop
                  Sum := Sum + Natural (Data (I));
               end loop;
               Emit ("TRY " & AHT.Transport.TLS.Read_Status'Image (Status)
                 & Natural'Image (Last) & Natural'Image (Sum) & " "
                 & Duration'Image
                   (Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Start)));
            exception
               when E : others =>
                  Emit ("TRY_ERROR " & Ada.Exceptions.Exception_Name (E)
                    & " " & Ada.Exceptions.Exception_Message (E));
            end;
         elsif Command = "close" then
            Wire.Set_Write_Deadline (0.0);
            Start := Ada.Real_Time.Clock;
            Emit ("CLOSE_BEGIN");
            Wire.Close;
            Emit ("CLOSED " & Duration'Image
              (Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Start)));
            exit;
          elsif Command = "available" then
             Emit ("AVAILABLE" & Interfaces.C.int'Image
               (Available (Interfaces.C.int (Port))));
          elsif Command = "congest" then
            if Fill_Send_Buffer (Interfaces.C.int (Port)) /= 0 then
               raise Program_Error with "could not establish send backpressure";
            end if;
            Emit ("CONGESTED");
         elsif Command = "write" then
            Wire.Set_Write_Deadline (0.05);
            Start := Ada.Real_Time.Clock;
            begin
               Wire.Write ([1 => Character'Pos ('G')]);
               Emit ("WROTE");
            exception
               when E : others =>
                  Emit ("WRITE_ERROR " & Ada.Exceptions.Exception_Name (E) & " "
                    & Duration'Image
                      (Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Start))
                    & " connected=" & Boolean'Image (Wire.Is_Connected));
            end;
         else
            --  Zero means try-without-wait; a positive value measures the
            --  blocking alternative. No timeout is relabelled as clean EOF.
            Wire.Set_Read_Deadline (Duration'Value (Command));
            Start := Ada.Real_Time.Clock;
            begin
               Wire.Read (Data, Last);
               Emit ("READ " & Natural'Image (Last) & " " & Duration'Image
                 (Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Start)));
            exception
               when E : AHT.Transport.Timeout_Error =>
                  Emit ("TIMEOUT " & Duration'Image
                    (Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Start))
                    & " " & Ada.Exceptions.Exception_Message (E));
               when E : others =>
                  Emit ("READ_ERROR " & Ada.Exceptions.Exception_Name (E) & " "
                    & Ada.Exceptions.Exception_Message (E));
            end;
         end if;
      end;
   end loop;
exception
   when E : others =>
      Emit ("PROBE_ERROR " & Ada.Exceptions.Exception_Information (E));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
end TLS_Probe;