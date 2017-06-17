/**
 * pam_oauth2 - Test-Application using PAM-Interface
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

#define _GNU_SOURCE
#include <stdio.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
  misc_conv,
  NULL
};

int main (int argc, char **argv) {
  pam_handle_t *pamh = NULL;
  const char *user = NULL;
  int retval;
  
  if (argc > 2) {
    fprintf (stderr, "Usage: %s [username]\n", argv [0]);
    return 1;
  }
  
  if (argc == 2)
    user = argv [1];
  
  /* Start PAM-Interface */
  if ((retval = pam_start ("pam_test", user, &conv, &pamh)) != PAM_SUCCESS) {
    fprintf (stderr, "%s: pam_start failed, ret = %d\n", argv [0], retval);
    
    return 2;
  }
  
  /* Override user-promt to make it look nicer */
  pam_set_item (pamh, PAM_USER_PROMPT, "Authenticate as: ");
  
  /* Try to get the inital user for authentication */
  pam_get_item (pamh, PAM_USER, (const void **)&user);
  
  if (user != NULL)
    fprintf (stderr, "%s: Authentication as: %s\n", argv [0], user);
  
  /* Try to authenticate */
  if ((retval = pam_authenticate (pamh, 0)) != PAM_SUCCESS) {
    fprintf (stderr, "%s: pam_authenticate failed, ret = %d\n", argv [0], retval);
    return 3;
  }
  
  /* Try to authorize */
  if ((retval = pam_acct_mgmt (pamh, 0)) == PAM_SUCCESS) {
    /* Re-request the actual user as it may have changed during authentication */
    pam_get_item (pamh, PAM_USER, (const void **)&user);
    
    fprintf (stdout, "%s: Authenticated as %s\n", argv [0], user);
  } else
    fprintf (stdout, "%s: Not Authenticated\n", argv [0]);
  
  /* Cleanup */
  if (pam_end (pamh, retval) != PAM_SUCCESS) {
    fprintf (stderr, "%s: Failed to release\n", argv [0]);
    return 1;
  }
  
  return (retval == PAM_SUCCESS ? 0 : 1);
}
