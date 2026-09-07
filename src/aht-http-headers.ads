--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Containers.Indefinite_Vectors;
with Ada.Strings.Unbounded;

package AHT.HTTP.Headers is

   pragma Preelaborate;

   type Map is tagged private
     with Default_Initial_Condition => Count (Map) = 0;

   package Value_Vectors is new Ada.Containers.Indefinite_Vectors
     (Index_Type   => Positive,
      Element_Type => String);

   subtype Value_List is Value_Vectors.Vector;

   --  Number of individual header entries (multi-valued headers count once
   --  per value because they are stored as repeated entries — matching
   --  RFC 7230 §3.2.2 semantics).
   function Count (Self : Map) return Natural;

   procedure Set    (Self : in out Map; Name, Value : String)
     with Pre  => Name'Length > 0,
          Post => Self.Contains (Name);
   --  Replaces any existing entries for Name with a single Name/Value.

   procedure Append (Self : in out Map; Name, Value : String)
     with Pre  => Name'Length > 0,
          Post => Self.Contains (Name);

   procedure Remove (Self : in out Map; Name : String)
     with Post => not Self.Contains (Name);

   function Contains (Self : Map; Name : String) return Boolean;

   function Get (Self : Map; Name : String) return String;
   --  Returns the first value, or "" if absent.

   function Values (Self : Map; Name : String) return Value_List;
   --  Returns every value set for Name, in insertion order. Empty
   --  vector if absent. No combining is performed: some headers
   --  (notably Set-Cookie, RFC 6265 §3) are NOT comma-combinable,
   --  so the caller decides how to join them.

   procedure Iterate
     (Self    : Map;
      Process : not null access procedure (Name, Value : String));
   --  Names are yielded in their stored (lowercase) form.

private

   type Header_Entry is record
      Name  : Ada.Strings.Unbounded.Unbounded_String;  --  stored lowercase
      Value : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   package Entry_Vectors is new Ada.Containers.Indefinite_Vectors
     (Index_Type   => Positive,
      Element_Type => Header_Entry);

   function Invariant_Ok (V : Entry_Vectors.Vector) return Boolean;
   --  All names are lowercase and non-empty.

   type Map is tagged record
      Entries : Entry_Vectors.Vector;
   end record
     with Type_Invariant => Invariant_Ok (Map.Entries);

end AHT.HTTP.Headers;
