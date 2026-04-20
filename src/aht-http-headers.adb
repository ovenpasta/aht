with Ada.Characters.Handling;

package body AHT.HTTP.Headers is

   use Ada.Strings.Unbounded;

   function To_Lower (S : String) return String renames
     Ada.Characters.Handling.To_Lower;

   function Invariant_Ok (V : Entry_Vectors.Vector) return Boolean is
   begin
      for E of V loop
         if Length (E.Name) = 0 then
            return False;
         end if;
         declare
            N : constant String := To_String (E.Name);
         begin
            if N /= To_Lower (N) then
               return False;
            end if;
         end;
      end loop;
      return True;
   end Invariant_Ok;

   function Count (Self : Map) return Natural is
     (Natural (Self.Entries.Length));

   procedure Set (Self : in out Map; Name, Value : String) is
      Lower_Name : constant String := To_Lower (Name);
      I          : Natural := 1;
   begin
      --  Remove all existing entries with this name.
      while I <= Natural (Self.Entries.Length) loop
         if To_String (Self.Entries (I).Name) = Lower_Name then
            Self.Entries.Delete (I);
         else
            I := I + 1;
         end if;
      end loop;

      Self.Entries.Append
        (Header_Entry'
           (Name  => To_Unbounded_String (Lower_Name),
            Value => To_Unbounded_String (Value)));
   end Set;

   procedure Append (Self : in out Map; Name, Value : String) is
   begin
      Self.Entries.Append
        (Header_Entry'
           (Name  => To_Unbounded_String (To_Lower (Name)),
            Value => To_Unbounded_String (Value)));
   end Append;

   procedure Remove (Self : in out Map; Name : String) is
      Lower_Name : constant String := To_Lower (Name);
      I          : Natural := 1;
   begin
      while I <= Natural (Self.Entries.Length) loop
         if To_String (Self.Entries (I).Name) = Lower_Name then
            Self.Entries.Delete (I);
         else
            I := I + 1;
         end if;
      end loop;
   end Remove;

   function Contains (Self : Map; Name : String) return Boolean is
      Lower_Name : constant String := To_Lower (Name);
   begin
      for E of Self.Entries loop
         if To_String (E.Name) = Lower_Name then
            return True;
         end if;
      end loop;
      return False;
   end Contains;

   function Get (Self : Map; Name : String) return String is
      Lower_Name : constant String := To_Lower (Name);
   begin
      for E of Self.Entries loop
         if To_String (E.Name) = Lower_Name then
            return To_String (E.Value);
         end if;
      end loop;
      return "";
   end Get;

   function Values (Self : Map; Name : String) return Value_List is
      Lower_Name : constant String := To_Lower (Name);
      Result     : Value_List;
   begin
      for E of Self.Entries loop
         if To_String (E.Name) = Lower_Name then
            Result.Append (To_String (E.Value));
         end if;
      end loop;
      return Result;
   end Values;

   procedure Iterate
     (Self    : Map;
      Process : not null access procedure (Name, Value : String))
   is
   begin
      for E of Self.Entries loop
         Process.all (To_String (E.Name), To_String (E.Value));
      end loop;
   end Iterate;

end AHT.HTTP.Headers;
