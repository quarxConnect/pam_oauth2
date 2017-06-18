#include <stdbool.h>
#include <time.h>

#ifdef DEBUG_SYSLOG
#  include <syslog.h>
#  define LDEBUG(fmt...) syslog(LOG_AUTH|LOG_DEBUG,fmt);
#elif DEBUG
#  include <stdio.h>
#  define LDEBUG(fmt...) fprintf(stderr, fmt);
#else
#  define LDEBUG(fmt...)
#endif

struct pam_oauth2_options {
  char *token_endpoint;
  char *revoke_endpoint;
  char *introspection_endpoint;
  char *client_username;
  char *client_password;
  char *username_path;
  char *scope;
  bool do_codeauth;
  bool do_tokenauth;
  bool do_passwordauth;
  bool do_clientauth;
};

struct pam_oauth2_token {
  char *token;
  char *refresh;
  time_t issued_at;
  time_t expires_at;
};

struct pam_oauth2_userinfo {
  char *desired_username;
  char *original_username;
  char *scope;
};

struct pam_oauth2_token *pam_oauth2_token_new ();
void pam_oauth2_token_free (struct pam_oauth2_token *token);

struct pam_oauth2_token *pam_oauth2_auth_code (struct pam_oauth2_options *options, char *code);
struct pam_oauth2_token *pam_oauth2_auth_password (struct pam_oauth2_options *options, char *username, char *password);
struct pam_oauth2_token *pam_oauth2_auth_client (struct pam_oauth2_options *options);

struct pam_oauth2_token *pam_oauth2_refresh (struct pam_oauth2_options *options, struct pam_oauth2_token *token);
void pam_oauth2_revoke (struct pam_oauth2_options *options, struct pam_oauth2_token *token);

struct pam_oauth2_userinfo *pam_oauth2_userinfo (struct pam_oauth2_options *options, char *token);
void pam_oauth2_userinfo_free (struct pam_oauth2_userinfo *info);

struct pam_oauth2_options *pam_oauth2_options_parse (int argc, const char **argv);
void pam_oauth2_options_free (struct pam_oauth2_options *options);
