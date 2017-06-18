/**
 * OAuth 2.0 Authentication for PAM
 * 
 * This PAM-Module implements OAuth 2.0 Authentication for PAM using
 * standard-methods from RFC 6749, RFC 7009 and RFC 7662 and no propietary
 * stuff at all.
 * 
 * Depending on configuration all authentication-schems from RFC 6749
 * are supported while redirection to a login-page of the OAuth 2.0
 * service is not supported due to the nature of PAM-Modules - this
 * has to be done out of band.
 * 
 * Authentication-methods may be combined to try as many as available.
 * Code- and Token-Authentication take precedence if "token-is-password"
 * was not provided as option.
 * 
 * Module-Parameters:
 *   auth-code                Try to retrive token with this grant-code
 *   auth-token               Try to retrive user-info with this token
 *   auth-password            Try to perform password-authentication
 *   auth-client              Try to perform client-authentication
 *                              using supplied username/password
 *   token-url={url}          Endpoint for Authentication (RFC 6749)
 *   revoke-url={url}         Endpoint for Token-Revocation (RFC 7009)
 *   introspection-url={url}  Endpoint for Token-Introspection
 *                              (RFC 7662)
 *   client-username={user}   Username of this OAuth2-Client
 *                              (for code, token and user-authentication)
 *   client-password={pass}   Password of this OAuth2-Client
 *                              (for code, token and user-authentication)
 *   username-path={path}     Extract and set username from introspection
 *   scope={scope}            Compare scopes on introspection
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
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-parser/json.h>
#include "pam_oauth2.h"

CURL *session = NULL;

struct pam_oauth2_response {
  char *ptr;
  size_t len;
};

static size_t pam_oauth2_receive (void *contents, size_t size, size_t nmemb, void *userp) {
  struct pam_oauth2_response *buffer = (struct pam_oauth2_response *)userp;
  size_t newsize = size * nmemb;
  
  if (!buffer->ptr) {
    buffer->ptr = malloc (newsize + 1);
    buffer->len = 0;
  } else
    buffer->ptr = realloc (buffer->ptr, buffer->len + newsize + 1);
  
  if (!buffer->ptr)
    return 0;
  
  memcpy (buffer->ptr + buffer->len, contents, newsize);
  buffer->len += newsize;
  buffer->ptr [buffer->len] = 0;
  
  return newsize;
}

char *pam_oauth2_fetch (char *url, char *username, char *password, struct curl_httppost* post) {
  CURLcode result;
  struct pam_oauth2_response response;
  
  /* Make sure response is correctly initialized */
  response.len = 0;
  response.ptr = NULL;
  
  /* Check wheter to initialize cURL-Session */
  if (session == NULL) {
    /* Create cURL-Session */
    session = curl_easy_init ();
    
    if (!session)
      return NULL;
    
    curl_easy_setopt (session, CURLOPT_POST , 1L);
    curl_easy_setopt (session, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt (session, CURLOPT_TIMEOUT, 5L);
#ifdef DEBUG
    curl_easy_setopt (session, CURLOPT_VERBOSE, 1L);
#endif
    
    curl_easy_setopt (session, CURLOPT_WRITEFUNCTION, pam_oauth2_receive);
    
    /* Setup headers */
    curl_easy_setopt (session, CURLOPT_HTTPHEADER, curl_slist_append (curl_slist_append (NULL, "Accept: application/json"), "Expect:"));
  }
  
  curl_easy_setopt (session, CURLOPT_URL, url);
  curl_easy_setopt (session, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt (session, CURLOPT_HTTPPOST, post);
  
  curl_easy_setopt (session, CURLOPT_USERNAME, username);
  curl_easy_setopt (session, CURLOPT_PASSWORD, password);
  
  /* Perform the request */
  if ((result = curl_easy_perform (session)) != CURLE_OK)
    return NULL;
  
  /* Return the result */
  return response.ptr;
}

json_value *pam_oauth2_json_get_name (json_value *root, char *name) {
  int p;
  
  /* Make sure there is a root */
  if (!root)
    return NULL;
  
  /* Make sure the root is an object */
  if (root->type != json_object)
    return NULL;
  
  /* Try to find the name */
  for (p = 0; p < root->u.object.length; p++)
    if (strcmp (root->u.object.values [p].name, name) == 0)
      return root->u.object.values [p].value;
  
  return NULL;
}

json_value *pam_oauth2_json_path (json_value *node, char *path, int length) {
  json_value *next = NULL;
  char *token = NULL, *value = NULL;
  int i;
  
  /* Make sure the node is valid */
  if (node == NULL)
    return NULL;
  
  /* Skip slashes at the beginning */
  while (path [0] == '/') {
    path++;
    length--;
  }

  /* Find next token */
  for (i = 0; i < length; i++)
    if (path [i] == '/') {
      token = strndup (path, i);
      path += i;
      length -= i;
      break;
    }
  
  if (token == NULL) {
    token = path;
    length = 0;
  }
  
  /* Check wheter to search for a value */
  for (i = 0; i < strlen (token); i++)
    if (token [i] == '=') {
      token [i] = 0;
      value = token + i + 1;
      break;
    }
  
  /* Try to match the token */
  if (strcmp (token, "..") == 0)
    next = node->parent;
  else if (strcmp (token, "*") == 0) {
    if (node->type == json_object) {
      for (i = 0; i < node->u.object.length; i++)
        if ((next = pam_oauth2_json_path (node->u.object.values [i].value, path, length)) != NULL) {
          length = 0;
          break;
        }
    } else if (node->type == json_array) {
      for (i = 0; i < node->u.array.length; i++)
        if ((next = pam_oauth2_json_path (node->u.array.values [i], path, length)) != NULL) {
          length = 0;
          break;
        }
    }
  } else if (node->type == json_object) {
    /* Search for member of that name */
    for (i = 0; i < node->u.object.length; i++)
      if (strcmp (node->u.object.values [i].name, token) == 0) {
        next = node->u.object.values [i].value;
        break;
      }
  } else if (node->type == json_array) {
    /* Retrive index of element */
    i = atoi (token);
    
    /* Access that element */
    if ((i >= 0) && (i < node->u.array.length))
      next = node->u.array.values [i];
  }
  
  /* Check for value */
  if ((value != NULL) && (next != NULL))
    if ((next->type != json_string) || (strcmp (value, next->u.string.ptr) != 0))
      next = NULL;

  /* Release memory */
  if (token != path)
    free (token);

  /* Check wheter to proceed */
  if ((next != NULL) && (length > 0))
    return pam_oauth2_json_path (next, path, length);
  
  return next;
}

struct pam_oauth2_token *pam_oauth2_token_new () {
  struct pam_oauth2_token *result = NULL;
  
  if ((result = malloc (sizeof (struct pam_oauth2_token))) == NULL)
    return NULL;
  
  memset (result, 0, sizeof (struct pam_oauth2_token));
  
  result->issued_at = time (NULL);
  
  return result;
}

void pam_oauth2_token_free (struct pam_oauth2_token *token) {
  if (token == NULL)
    return;
  
  if (token->token != NULL)
    free (token->token);
  
  if (token->refresh != NULL)
    free (token->refresh);
  
  free (token);
}

struct pam_oauth2_token *pam_oauth2_access_token (char *url, char *username, char *password, struct curl_httppost* post) {
  json_value *root, *node;
  char *response, *token;
  struct pam_oauth2_token *result = NULL;
  
  /* Perform the request */
  if ((response = pam_oauth2_fetch (url, username, password, post)) == NULL)
    return NULL;
  
  /* Try to parse the JSON */
  root = json_parse (response, strlen (response));
  free (response);
  
  if ((node = pam_oauth2_json_get_name (root, "access_token")) == NULL)
    goto finish;
  
  if (node->type != json_string)
    goto finish;
  
  /* Create the result */
  if ((result = pam_oauth2_token_new ()) == NULL)
    goto finish;
  
  /* Copy the token from JSON and terminte it */
  if ((result->token = malloc (node->u.string.length + 1)) == NULL)
    goto failure;
  
  memcpy (result->token, node->u.string.ptr, node->u.string.length);
  result->token [node->u.string.length] = 0;
  
  /* Check if there is a refresh-token */
  if (((node = pam_oauth2_json_get_name (root, "refresh_token")) != NULL) &&
      (node->type == json_string) &&
      ((result->refresh = malloc (node->u.string.length + 1)) != NULL)) {
    memcpy (result->refresh, node->u.string.ptr, node->u.string.length);
    result->refresh [node->u.string.length] = 0;
  }
  
  /* Check if there is an expiration-time given */
  if (((node = pam_oauth2_json_get_name (root, "expires_in")) != NULL) &&
      (node->type == json_integer))
    result->expires_at = result->issued_at + node->u.integer;
  else
    result->expires_at = result->issued_at + 3600;

finish:
  /* Free the JSON-Structure */
  json_value_free (root);
  
  /* Return the token */
  return result;
  
failure:
  /* Cleanup on error */
  free (result);
  result = NULL;
  
  goto finish;
}

struct pam_oauth2_token *pam_oauth2_auth_code (struct pam_oauth2_options *options, char *code) {
  /* Create a new cURL-Session */
  struct curl_httppost* post = NULL;
  struct curl_httppost* last = NULL;
  struct pam_oauth2_token *result;
  
  /* Setup OAuth2-Request */
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "grant_type", CURLFORM_COPYCONTENTS, "authorization_code", CURLFORM_END);
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "code", CURLFORM_COPYCONTENTS, code, CURLFORM_END);
  
  /* Try to perform the request */
  result = pam_oauth2_access_token (options->token_endpoint, options->client_username, options->client_password, post);
  
  /* Cleanup */
  curl_formfree (post);
  
  /* Forward the result */
  return result;
}

struct pam_oauth2_token *pam_oauth2_auth_password (struct pam_oauth2_options *options, char *username, char *password) {
  /* Create a new cURL-Session */
  struct curl_httppost* post = NULL;
  struct curl_httppost* last = NULL;
  struct pam_oauth2_token *result;
  
  /* Setup OAuth2-Request */
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "grant_type", CURLFORM_COPYCONTENTS, "password", CURLFORM_END);
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "username", CURLFORM_COPYCONTENTS, username, CURLFORM_END);
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "password", CURLFORM_COPYCONTENTS, password, CURLFORM_END);
  
  /* Try to perform the request */
  result = pam_oauth2_access_token (options->token_endpoint, options->client_username, options->client_password, post);
  
  /* Cleanup */
  curl_formfree (post);
  
  /* Forward the result */
  return result;
}

struct pam_oauth2_token *pam_oauth2_auth_client (struct pam_oauth2_options *options) {
  /* Create a new cURL-Session */
  struct curl_httppost* post = NULL;
  struct curl_httppost* last = NULL;
  struct pam_oauth2_token *result;
  
  /* Setup OAuth2-Request */
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "grant_type", CURLFORM_COPYCONTENTS, "client_credentials", CURLFORM_END);
  
  /* Try to perform the request */
  result = pam_oauth2_access_token (options->token_endpoint, options->client_username, options->client_password, post);
  
  /* Cleanup */
  curl_formfree (post);
  
  /* Forward the result */
  return result;
}

struct pam_oauth2_token *pam_oauth2_refresh (struct pam_oauth2_options *options, struct pam_oauth2_token *token) {
  /* Make sure its a token */
  if (token == NULL)
    return NULL;
  
  /* Make sure there is a refresh-token */
  if ((token->refresh == NULL) && (token->token == NULL))
    return NULL;
  
  struct curl_httppost* post = NULL;
  struct curl_httppost* last = NULL;
  struct pam_oauth2_token *result;
  
  /* Setup OAuth2-Request */
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "grant_type", CURLFORM_COPYCONTENTS, "refresh_token", CURLFORM_END);
  
  if (token->refresh != NULL)
    curl_formadd (&post, &last, CURLFORM_COPYNAME, "refresh_token", CURLFORM_COPYCONTENTS, token->refresh, CURLFORM_END);
  else
    curl_formadd (&post, &last, CURLFORM_COPYNAME, "refresh_token", CURLFORM_COPYCONTENTS, token->token, CURLFORM_END);
  
  /* Try to perform the request */
  result = pam_oauth2_access_token (options->token_endpoint, options->client_username, options->client_password, post);
  
  /* Cleanup */
  curl_formfree (post);

  /* Forward the result */
  return result;
}

void pam_oauth2_revoke (struct pam_oauth2_options *options, struct pam_oauth2_token *token) {
  /* Make sure its a token */
  if ((token == NULL) || (options == NULL))
    return;

  /* Make sure there is a token */
  if (token->token == NULL)
    return;

  struct curl_httppost* post = NULL;
  struct curl_httppost* last = NULL;

  /* Setup OAuth2-Request */
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "token", CURLFORM_COPYCONTENTS, token->token, CURLFORM_END);

  /* Try to perform the request */
  pam_oauth2_fetch (options->revoke_endpoint, options->client_username, options->client_password, post);
  
  /* Cleanup */
  curl_formfree (post);
}

struct pam_oauth2_userinfo *pam_oauth2_userinfo (struct pam_oauth2_options *options, char *token) {
  struct curl_httppost* post = NULL;
  struct curl_httppost* last = NULL;
  struct pam_oauth2_userinfo *result = NULL;
  json_value *root, *node;
  char *response;
  
  /* Prepare the form */
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "token", CURLFORM_COPYCONTENTS, token, CURLFORM_END);
  curl_formadd (&post, &last, CURLFORM_COPYNAME, "token_type_hint", CURLFORM_COPYCONTENTS, "access_token", CURLFORM_END);
  
  /* Try to fetch */
  if ((response = pam_oauth2_fetch (options->introspection_endpoint, options->client_username, options->client_password, post)) == NULL)
    return NULL;
  
  /* Clean up the request-form */
  curl_formfree (post);
  
  /* Try to parse the JSON */
  root = json_parse (response, strlen (response));
  free (response);
  
  /* Make sure the access-token is active */
  if ((node = pam_oauth2_json_get_name (root, "active")) == NULL)
    return NULL;
  
  if (node->type != json_boolean)
    return NULL;
  
  if (!node->u.boolean)
    return NULL;
  
  /* Allocate userinfo-result */
  result = malloc (sizeof (struct pam_oauth2_userinfo));
  memset (result, 0, sizeof (struct pam_oauth2_userinfo));
  
  /* Copy scope if there is one */
  if (((node = pam_oauth2_json_get_name (root, "scope")) != NULL) &&
      (node->type == json_string))
    result->scope = strdup (node->u.string.ptr);
  
  /* Check for original username */
  if (((node = pam_oauth2_json_get_name (root, "username")) != NULL) &&
      (node->type == json_string))
    result->original_username = strdup (node->u.string.ptr);
  
  /* Check for desired username */
  if ((options->username_path != NULL) &&
      ((node = pam_oauth2_json_path (root, options->username_path, strlen (options->username_path))) != NULL) &&
      (node->type == json_string))
    result->desired_username = strdup (node->u.string.ptr);
  
  LDEBUG ("Original username %s", result->original_username);
  LDEBUG ("Desired username %s from %s\n", result->desired_username, options->username_path);
  LDEBUG ("Scopes %s, requred %s\n", result->scope, options->scope);
  
  /* Free the JSON-Structure */
  json_value_free (root);
  
  return result;
}

void pam_oauth2_userinfo_free (struct pam_oauth2_userinfo *info) {
  if (info == NULL)
    return;
  
  if (info->original_username != NULL)
    free (info->original_username);
  
  if (info->desired_username != NULL)
    free (info->desired_username);
  
  if (info->scope != NULL)
    free (info->scope);
  
  free (info);
}

struct pam_oauth2_options *pam_oauth2_options_parse (int argc, const char **argv) {
  struct pam_oauth2_options *options;
  int opt;
  
  /* Allocate space */
  if ((options = malloc (sizeof (struct pam_oauth2_options))) == NULL)
    return NULL;
  
  memset (options, 0, sizeof (struct pam_oauth2_options));
  
  /* Parse all options */
  for (opt = 0; opt < argc; opt++)
    if (strcmp (argv [opt], "auth-code") == 0)
      options->do_codeauth = true;
    else if (strcmp (argv [opt], "auth-token") == 0)
      options->do_tokenauth = true;
    else if (strcmp (argv [opt], "auth-password") == 0)
      options->do_passwordauth = true;
    else if (strcmp (argv [opt], "auth-client") == 0)
      options->do_clientauth = true;
    else if (strncmp (argv [opt], "client-username=", 16) == 0)
      options->client_username = strdup (argv [opt] + 16);
    else if (strncmp (argv [opt], "client-password=", 16) == 0)
      options->client_password = strdup (argv [opt] + 16);
    else if (strncmp (argv [opt], "token-url=", 10) == 0)
      options->token_endpoint = strdup (argv [opt] + 10);
    else if (strncmp (argv [opt], "revoke-url=", 11) == 0)
      options->revoke_endpoint = strdup (argv [opt] + 11);
    else if (strncmp (argv [opt], "introspection-url=", 18) == 0)
      options->introspection_endpoint = strdup (argv [opt] + 18);
    else if (strncmp (argv [opt], "username-path=", 14) == 0)
      options->username_path = strdup (argv [opt] + 14);
    else if (strncmp (argv [opt], "scope=", 6) == 0)
      options->scope = strdup (argv [opt] + 6);
  
  return options;
}

void pam_oauth2_options_free (struct pam_oauth2_options *options) {
  if (options == NULL)
    return;
  
  if (options->client_username)
    free (options->client_username);
  
  if (options->client_password)
    free (options->client_password);
  
  if (options->token_endpoint)
    free (options->token_endpoint);
  
  if (options->revoke_endpoint)
    free (options->revoke_endpoint);
  
  if (options->introspection_endpoint)
    free (options->introspection_endpoint);
  
  if (options->username_path)
    free (options->username_path);
  
  if (options->scope)
    free (options->scope);
  
  free (options);
}
