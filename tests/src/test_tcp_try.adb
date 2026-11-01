--  Copyright (C) 2026 Zack Boll
--  SPDX-License-Identifier: Apache-2.0

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Streams; use Ada.Streams;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets; use GNAT.Sockets;
with AHT.Bytes;
with AHT.Transport.TCP;
with AHT.URL;

procedure Test_TCP_Try is
   Listener, Peer : Socket_Type := No_Socket;
   Address : Sock_Addr_Type;
   T : AHT.Transport.TCP.TCP_Transport;
   Data : AHT.Bytes.Byte_Array (7 .. 32);
   Chunk : constant AHT.Bytes.Byte_Array (1 .. 65_536) := [others => 42];
   Last, Sent, Total : Natural := 0;
   Status : AHT.Transport.TCP.Read_Status;
   use type AHT.Transport.TCP.Read_Status;
   Got : Stream_Element_Offset;
   Deadline : Time;
begin
   Create_Socket (Listener);
   Bind_Socket (Listener, (Family_Inet, Inet_Addr ("127.0.0.1"), 0));
   Listen_Socket (Listener);
   T.Connect ("127.0.0.1", AHT.URL.Port_Number (Get_Socket_Name (Listener).Port),
              Connect_Timeout => 1.0);
   Accept_Socket (Listener, Peer, Address);
   T.Set_Read_Deadline (0.0);
   T.Set_Write_Deadline (0.0);
   T.Try_Read (Data, Last, Status);
   pragma Assert (Status = AHT.Transport.TCP.Idle and then Last = 0);
   T.Try_Read (Data (7 .. 6), Last, Status);
   pragma Assert (Status = AHT.Transport.TCP.Idle and then Last = 0);
   T.Try_Write (Chunk (1 .. 0), Sent);
   pragma Assert (Sent = 0);
   Send_Socket (Peer, [1 => 65, 2 => 66], Got);
   pragma Assert (Got = 2);
   Deadline := Clock + Seconds (1);
   loop
      T.Try_Read (Data, Last, Status);
      exit when Status /= AHT.Transport.TCP.Idle;
      pragma Assert (Clock < Deadline);
   end loop;
   pragma Assert (Status = AHT.Transport.TCP.Data_Ready and then Last = 8);
   pragma Assert (Natural (Data (7)) = 65 and then Natural (Data (8)) = 66);
   --  A peer that does not read eventually fills the real socket send
   --  buffer. Every call is a partial, nonblocking attempt, not Write.
   Deadline := Clock + Seconds (5);
   loop
      T.Try_Write (Chunk, Sent);
      pragma Assert (Sent <= 16_384);
      exit when Sent = 0;
      Total := Total + Sent;
      pragma Assert (Clock < Deadline);
   end loop;
   pragma Assert (Total > 0);
   Shutdown_Socket (Peer, Shut_Write);
   Deadline := Clock + Seconds (1);
   loop
      T.Try_Read (Data, Last, Status);
      exit when Status /= AHT.Transport.TCP.Idle;
      pragma Assert (Clock < Deadline);
   end loop;
   pragma Assert (Status = AHT.Transport.TCP.Peer_Closed and then Last = 0);
   T.Close;
   T.Close;
   Close_Socket (Peer);
   Close_Socket (Listener);
   Put_Line ("test_tcp_try: OK (idle/data/EOF, shifted indices, bounded sends, backpressure)");
exception
   when E : others =>
      Put_Line ("test_tcp_try: FAIL " & Ada.Exceptions.Exception_Information (E));
      T.Close;
      if Peer /= No_Socket then
         Close_Socket (Peer);
      end if;
      if Listener /= No_Socket then
         Close_Socket (Listener);
      end if;
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
end Test_TCP_Try;