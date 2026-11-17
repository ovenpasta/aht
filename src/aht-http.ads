--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package AHT.HTTP is

   pragma Pure;

   HTTP_Error     : exception;
   Protocol_Error : exception;
   Redirect_Error : exception;
   --  A redirect AHT.HTTP.Client will not follow: more than
   --  Max_Redirects, a Location that does not parse or names a scheme
   --  other than http and https, or an https to http downgrade.

end AHT.HTTP;
