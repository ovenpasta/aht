package body AHT.HTTP.Status is

   function Reason_Phrase (Code : Status_Code) return String is
   begin
      case Code is
         when 100 => return "Continue";
         when 101 => return "Switching Protocols";
         when 200 => return "OK";
         when 201 => return "Created";
         when 202 => return "Accepted";
         when 204 => return "No Content";
         when 301 => return "Moved Permanently";
         when 302 => return "Found";
         when 304 => return "Not Modified";
         when 400 => return "Bad Request";
         when 401 => return "Unauthorized";
         when 403 => return "Forbidden";
         when 404 => return "Not Found";
         when 405 => return "Method Not Allowed";
         when 408 => return "Request Timeout";
         when 426 => return "Upgrade Required";
         when 500 => return "Internal Server Error";
         when 501 => return "Not Implemented";
         when 502 => return "Bad Gateway";
         when 503 => return "Service Unavailable";
         when 504 => return "Gateway Timeout";
         when others => return "";
      end case;
   end Reason_Phrase;

end AHT.HTTP.Status;
