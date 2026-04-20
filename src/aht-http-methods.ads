package AHT.HTTP.Methods is

   pragma Pure;

   type Method_Type is (GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS);

   function Image (M : Method_Type) return String is
     (case M is
        when GET     => "GET",
        when POST    => "POST",
        when PUT     => "PUT",
        when DELETE  => "DELETE",
        when HEAD    => "HEAD",
        when PATCH   => "PATCH",
        when OPTIONS => "OPTIONS");

end AHT.HTTP.Methods;
