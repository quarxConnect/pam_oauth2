CC = gcc

# We would have loved to use -std=c90/-ansi and -pedantic here,
# but at least PAM (pam-misc) prevents us from doing so
CFLAGS  += -Werror -fPIC $(PAM_CFLAGS) $(CURL_CFLAGS) $(JSON_PARSER_CFLAGS)
LDFLAGS += -Wl,--strip-all $(PAM_LDFLAGS) $(CURL_LDFLAGS) $(JSON_PARSER_LDFLAGS)

# qcCore3-Stuff. Externals should ignore this.
PAM_VERSION         = latest
CURL_VERSION        = latest
JSON_PARSER_VERSION = latest

PAM_CFLAGS          = -I/system/apps/pam/$(PAM_VERSION)/include
PAM_LDFLAGS         = -L/system/apps/pam/$(PAM_VERSION)/lib -Wl,-rpath,/system/apps/pam/$(PAM_VERSION)/lib
CURL_CFLAGS         = -I/system/apps/curl/$(CURL_VERSION)/include
CURL_LDFLAGS        = -L/system/apps/curl/$(CURL_VERSION)/lib -Wl,-rpath,/system/apps/curl/$(CURL_VERSION)/lib
JSON_PARSER_CFLAGS  = -I/system/apps/json-parser/$(JSON_PARSER_VERSION)/include
JSON_PARSER_LDFLAGS = -L/system/apps/json-parser/$(JSON_PARSER_VERSION)/lib -Wl,-rpath,/system/apps/json-parser/$(JSON_PARSER_VERSION)/lib

# Targets
all:	pam cli test

debug:	CFLAGS +=-DDEBUG
debug:	all

debug-syslog:	CFLAGS +=-DDEBUG_SYSLOG
debug-syslog:	all

# Build CLI-Testprogramm to interface pam_oauth2 directly
cli:	pam_oauth2_core.o pam_oauth2_cli.o
	$(CC) $(LDFLAGS) $^ -lpam -lcurl -ljsonparser -o pam_oauth2

# Build the actual pam-module
pam:	pam_oauth2_core.o pam_oauth2_pamlib.o
	$(CC) $(LDFLAGS) $^ -lpam -lcurl -ljsonparser -shared -o pam_oauth2.so

# Build a test-application to start dummy pam-authentications
test:	pam_test.o
	$(CC) $(LDFLAGS) $^ -lpam -lpam_misc -o pam_test

# Clean up everything
clean:
	-rm *.o *.so pam_test pam_oauth2
