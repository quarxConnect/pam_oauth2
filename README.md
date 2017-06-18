# pam_oauth2
OAuth2-Module for PAM. Implemented with respect to RFC 6749, RFC 7009 and
RFC 7662, propietary stuff like Google and Facebook are left out.

Authentication (RFC 6749) may be done by using a grant-code that is
transformed into a token, a token itself and finally - of course - with a
username/password-pair employed to password- and client-authentication.

Token-Introspection (RFC 7662) offers capabilties to check the validity
of a token and allows to override the username used for authentication at
the calling application.

For applications that make use of pam_setcred(3) or pam-sessions tokens
may be revoked at end of the session by using an RFC 7009
revocation-endpoint.

## Requirements

*  [Linux-Pam](http://www.linux-pam.org/)
*  [cURL](https://curl.haxx.se/)
*  [json-parser](https://github.com/udp/json-parser)

## Building
The project contains a `Makefile` that should be suitable for most
linux-environments as long as all required libraries may be found at
standard-locations. For our own environment there is some propietary
stuff that should not bother you.

Just run

~~~ {.bash}
make pam
~~~

to build the PAM-Module. If there are no errors, you'll find a file
called `pam_oauth2.so` in the project-directory that may be copied to a
better location like `/lib/security` (or the one prefered by you
distribution).

There are two other targets on the `Makefile`:

| Target | Purpose                                                                                                      |
|--------|--------------------------------------------------------------------------------------------------------------|
| test   | Build a testing-application called `pam_test` that acts as PAM-Application trying to gain authentication     |
| cli    | Build a testing-application called `pam_oauth2` that directly interfaces pam_oauth2 without using PAM at all |

## Usage
The module may be used as authentication-, account- and/or
session-module. If used as account- or session-module, make sure to use
it as authentication-module as well as this is always required.

Example `/etc/pam.conf`:

~~~
pam_test	auth		required	pam_oauth2.so	token-url={url} introspection-url={url} revoke-url={url} client-username={name} client-password={pass} username-path=/jcard/1/*/0=username/../3 auth-password
pam_test	account		required	pam_oauth2.so	introspection-url={url} client-username={name} client-password={pass} username-path=/jcard/1/*/0=username/../3
pam_test	session		required	pam_oauth2.so	revoke-url={url} client-username={name} client-password={pass}
~~~

### Parameters
`pam_oauth2` is aware of these parameters:

| Parameter               | Description                                                                                   |
|-------------------------|-----------------------------------------------------------------------------------------------|
| token-url={url}         | URL of Token-Endpoint (RFC 6749)                                                              |
| revoke-url={url}        | URL of Revocation-Endpoint (RFC 7009)                                                         |
| introspection-url={url} | URL of Introspection-Endpoint (RFC 7662)                                                      |
| client-username={user}  | Username of the authentication-client                                                         |
| client-password={path}  | Password of the authentication-client                                                         |
| auth-code               | Try to perform authentication using a grant-code                                              |
| auth-token              | Try to perform authentication using an already established token                              |
| auth-password           | Try to perform authentication using password-authentication                                   |
| auth-client             | Try to perform client-authentication (not using client-credentials from above)                |
| username-path={path}    | Try to extract actual username from introspection-response using this path                    |
| scope={scope}           | Compare granted scopes on introspection-response with this scope. Fails if not present.       |
