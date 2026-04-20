package AHT.HTTP.Status is

   pragma Pure;

   subtype Status_Code is Integer
     with Static_Predicate => Status_Code in 100 .. 599;

   function Reason_Phrase (Code : Status_Code) return String;

end AHT.HTTP.Status;
