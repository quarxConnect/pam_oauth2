/**
 * pam_oauth2 - PAM-Interface
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

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION

#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include "pam_oauth2.h"

#define PAM_OAUTH2_ERROR(fmt...) pam_syslog (pamh, LOG_AUTH|LOG_ERR, fmt);
#if defined(DEBUG) || defined(DEBUG_SYSLOG)
#define PAM_OAUTH2_DEBUG(fmt...) pam_syslog (pamh, LOG_AUTH|LOG_DEBUG, fmt);
#else
#define PAM_OAUTH2_DEBUG(fmt...)
#endif

void pam_oauth2_token_freep (pam_handle_t *pamh, void *data, int error_status) {
  pam_oauth2_token_free ((struct pam_oauth2_token *)data);
}

void pam_oauth2_userinfo_freep (pam_handle_t *pamh, void *data, int error_status) {
  pam_oauth2_userinfo_free ((struct pam_oauth2_userinfo *)data);
}

#ifdef PAM_SM_AUTH
PAM_EXTERN int pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv) {
  struct pam_oauth2_options *options;
  struct pam_oauth2_token *oauth_token = NULL;
  struct pam_oauth2_userinfo *info = NULL;
  char *username = NULL, *token = NULL, *cuser = NULL, *cpasswd = NULL;
  bool check_username = false;
  int result = PAM_AUTHINFO_UNAVAIL;
  
  /* Parse all options */
  if ((options = pam_oauth2_options_parse (argc, argv)) == NULL) {
    PAM_OAUTH2_ERROR ("Failed to parse options");
    
    return PAM_AUTHINFO_UNAVAIL;
  }
  
  /* Check if there is anything to do */
  if (!(options->do_codeauth || options->do_tokenauth || options->do_passwordauth || options->do_clientauth)) {
    PAM_OAUTH2_ERROR ("No authentication-methods enabled at all");
    goto cleanup;
  }
  
  /* Retrive username */
  if ((pam_get_user (pamh, (const char **)&username, NULL) != PAM_SUCCESS) || (username == NULL)) {
    PAM_OAUTH2_ERROR ("Failed to retrive username");
    goto cleanup;
  }
  
  /* Retrive password */
  if ((pam_get_authtok (pamh, PAM_AUTHTOK, (const char **)&token, NULL) != PAM_SUCCESS) || (token == NULL)) {
    PAM_OAUTH2_ERROR ("Failed to retrive authentication-token");
    goto cleanup;
  }
  
  /* Check wheter code- and token-authentication may be used */
  if (options->username_path != NULL) {
    /* Try to use a code-grant for authentication */
    if (options->do_codeauth) {
      if ((oauth_token = pam_oauth2_auth_code (options, token)) != NULL)
        check_username = true;
      
      PAM_OAUTH2_DEBUG ("Code-Authentication using token: %s", (oauth_token != NULL ? "successfull" : "failed"));
    }
    
    /* Try to do token-authentication */  
    if ((oauth_token == NULL) && options->do_tokenauth) {
      if ((info = pam_oauth2_userinfo (options, token)) != NULL) {
        check_username = true;
        
        if ((oauth_token = pam_oauth2_token_new ()) != NULL)
          oauth_token->token = token;
      }
      
      PAM_OAUTH2_DEBUG ("Token-Authentication using token: %s", (oauth_token != NULL ? "successfull" : "failed"));
    }
  } else if (options->do_codeauth || options->do_tokenauth)
    PAM_OAUTH2_ERROR ("Skipping code-grant- and token-authentication because there is no username-path to check");
  
  /* Try to do password-authentication */
  if ((oauth_token == NULL) && options->do_passwordauth) {
    oauth_token = pam_oauth2_auth_password (options, username, token);
    PAM_OAUTH2_DEBUG ("Password-Authentication: %s", (oauth_token != NULL ? "successfull" : "failed"));
  }
  
  /* Try to do client-authentication */
  if ((oauth_token == NULL) && options->do_clientauth) {
    /* Replace client-credentials on options */
    cuser = options->client_username;
    cpasswd = options->client_password;
    
    if ((username != NULL) && (token != NULL)) {
      options->client_username = username;
      options->client_password = token;
    }
    
    /* Try to do client-authentication */
    oauth_token = pam_oauth2_auth_client (options);
    PAM_OAUTH2_DEBUG ("Client-Authentication: %s", (oauth_token != NULL ? "successfull" : "failed"));
    
    /* Restore the credentials */
    options->client_username = cuser;
    options->client_password = cpasswd;
  }
  
  /* Check if we got something usefull */
  if ((oauth_token == NULL) && (info == NULL)) {
    PAM_OAUTH2_DEBUG ("Could not retrive token and/or userinfo");
    result = PAM_AUTH_ERR;
    goto cleanup;
  }
  
  if ((info == NULL) && ((info = pam_oauth2_userinfo (options, oauth_token->token)) == NULL)) {
    PAM_OAUTH2_ERROR ("Failed tro retrive userinfo");
    result = PAM_AUTH_ERR;
    goto cleanup;
  }
  
  /* Check username if required */
  if (check_username &&
      ((info->original_username == NULL) || (strcmp (info->original_username, username) != 0)) &&
      ((info->desired_username == NULL) || (strcmp (info->desired_username, username) != 0))) {
    PAM_OAUTH2_ERROR ("Usernames do not match");
    result = PAM_AUTH_ERR;
    goto cleanup;
  }
  
  /* Forward desired username if there is one */
  if (info->desired_username != NULL)
    pam_set_item (pamh, PAM_USER, info->desired_username);
  
  /* Store some internal settings */
  pam_set_data (pamh, "pam_oauth2_token", oauth_token, pam_oauth2_token_freep);
  pam_set_data (pamh, "pam_oauth2_userinfo", info, pam_oauth2_userinfo_freep);
  
  /* Mark auth as successfull if we get here */
  result = PAM_SUCCESS;
  
cleanup:
  pam_oauth2_options_free (options);
  
  /* Only if pointers are not used elsewhere */
  if (result != PAM_SUCCESS) {
    if (oauth_token != NULL)
      pam_oauth2_token_free (oauth_token);
  
    if (info != NULL)
      pam_oauth2_userinfo_free (info);
  }
  
  return result;
}

PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv) {
  struct pam_oauth2_options *options;
  struct pam_oauth2_token *token;
  struct pam_oauth2_userinfo *info;
  int result = PAM_AUTHINFO_UNAVAIL;
  
  /* Parse all options */
  if ((options = pam_oauth2_options_parse (argc, argv)) == NULL) {
    PAM_OAUTH2_ERROR ("Failed to parse options");
    
    return PAM_AUTHINFO_UNAVAIL;
  }
  
  /* Make sure we have a current token */
  if ((pam_get_data (pamh, "pam_oauth2_token", (const void **)&token) != PAM_SUCCESS) || (token == NULL))
    return PAM_AUTHINFO_UNAVAIL;
  
  /* Check wheter to remove credentials */
  if ((flags & PAM_DELETE_CRED) == PAM_DELETE_CRED) {
    pam_oauth2_revoke (options, token);
    pam_set_data (pamh, "pam_oauth2_token", NULL, NULL);
    
    return PAM_SUCCESS;
  }
  
  /* Check wheter to (re)initialize credentials */
  if (((flags & PAM_ESTABLISH_CRED) == PAM_ESTABLISH_CRED) ||
      ((flags & PAM_REINITIALIZE_CRED) == PAM_REINITIALIZE_CRED)) {
    /* Fetch token-introspection from service */
    if (((flags & PAM_REINITIALIZE_CRED) == PAM_REINITIALIZE_CRED) ||
        ((pam_get_data (pamh, "pam_oauth2_userinfo", (const void **)&info) != PAM_SUCCESS) || (info == NULL))) {
      if ((info = pam_oauth2_userinfo (options, token->token)) == NULL)
        return PAM_CRED_EXPIRED;
      
      pam_set_data (pamh, "pam_oauth2_userinfo", info, pam_oauth2_userinfo_freep);
    }
    
    /* Check wheter to forward the username */
    if (info->desired_username != NULL)
      pam_set_item (pamh, PAM_USER, info->desired_username);
    
    result = PAM_SUCCESS;
  }
  
  /* Check wheter to refresh credentials */
  if ((flags & PAM_REFRESH_CRED) == PAM_REFRESH_CRED) {
    if (pam_oauth2_refresh (options, token) == NULL)
      return PAM_CRED_EXPIRED;
    
    return PAM_SUCCESS;
  }
  
  return result;
}
#endif

#ifdef PAM_SM_ACCOUNT
PAM_EXTERN int pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv) {
  struct pam_oauth2_options *options;
  struct pam_oauth2_token *token;
  struct pam_oauth2_userinfo *info;
  char *scopes, *scope;
  int result = PAM_AUTH_ERR;
  
  /* Parse all options */
  if ((options = pam_oauth2_options_parse (argc, argv)) == NULL) {
    PAM_OAUTH2_ERROR ("Failed to parse options");
    
    return PAM_AUTH_ERR;
  }
  
  /* Make sure we have a current token */
  if ((pam_get_data (pamh, "pam_oauth2_token", (const void **)&token) != PAM_SUCCESS) || (token == NULL)) {
    PAM_OAUTH2_ERROR ("Trying to authorize without having authenticated first");
    goto cleanup;
  }
  
  /* Check expiration-time */
  if (token->expires_at < time (NULL)) {
    result = PAM_ACCT_EXPIRED;
    goto cleanup;
  }
  
  /* Check the scope */
  if (options->scope != NULL) {
    /* Fetch token-introspection from service */
    if ((pam_get_data (pamh, "pam_oauth2_userinfo", (const void **)&info) != PAM_SUCCESS) || (info == NULL)) {
      if ((info = pam_oauth2_userinfo (options, token->token)) == NULL) {
        PAM_OAUTH2_ERROR ("Could not fetch introspection");
        goto cleanup;
      }
  
      pam_set_data (pamh, "pam_oauth2_userinfo", info, pam_oauth2_userinfo_freep);
    }
    
    LDEBUG("Compare scopes %s with %s\n", info->scope, options->scope);
    
    /* Treat non existing-scopes as unauthorized */
    if (info->scope == NULL) {
      PAM_OAUTH2_ERROR ("No scopes granted at all (or at least missing on introspection)");
      result = PAM_PERM_DENIED;
      goto cleanup;
    }
    
    /* Check if one scope matches */
    scopes = strdup (info->scope);
    scope = strtok (scopes, " ");
    
    while (scope) {
      if (strcmp (scope, options->scope) == 0) {
        scope = options->scope;
        break;
      }
      
      scope = strtok (NULL, " ");
    }
    
    free (scopes);
    
    if (options->scope != scope) {
      PAM_OAUTH2_ERROR ("No matching scope found");
      result = PAM_PERM_DENIED;
      goto cleanup;
    }
  }
  
  /* Indicate success */
  result = PAM_SUCCESS;
  
cleanup:
  pam_oauth2_options_free (options);
  
  return result;
}
#endif
#ifdef PAM_SM_SESSION
PAM_EXTERN int pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv) {
  struct pam_oauth2_options *options;
  struct pam_oauth2_token *token;

  /* Parse all options */
  if ((options = pam_oauth2_options_parse (argc, argv)) == NULL) {
    PAM_OAUTH2_ERROR ("Failed to parse options");
    
    return PAM_SESSION_ERR;
  }
  
  /* Make sure we have a current token */
  if ((pam_get_data (pamh, "pam_oauth2_token", (const void **)&token) != PAM_SUCCESS) || (token == NULL))
    return PAM_SUCCESS;
  
  /* Revoke the token */
  pam_oauth2_revoke (options, token);
  
  return PAM_SUCCESS;
}
#endif
