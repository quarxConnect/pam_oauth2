/**
 * pam_oauth2 - command line interface
 * Copyright (C) 2017 Bernd Holzmueller <bernd@quarxconnect.de>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include <stdio.h>
#include <stdlib.h>
#include "pam_oauth2.h"

int main (int argc, const char **argv) {
  struct pam_oauth2_options *options;
  struct pam_oauth2_token *token;
  struct pam_oauth2_userinfo *info;
  
  /* Try to parse the options */
  if ((options = pam_oauth2_options_parse (argc, argv)) == NULL)
    return 1;
  
  /* Request the token */
  if (!(token = pam_oauth2_auth_password (options, "admin@example.com", "admin")))
    return 1;
  
  printf ("Got token: %s\n", token->token);
  
  /* Request user-info */
  if (!(info = pam_oauth2_userinfo (options, token->token))) {
    free (token);
    return 2;
  }
  
  /* Cleanup */
  free (token);
  free (info);
  
  return 0;
}
