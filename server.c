#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>

#include "internals/cyphers/rabin.h"
#include "internals/cyphers/rsa.h"
#include "internals/cyphers/enigma.h"
#include "internals/cyphers/shamir.h"
#include "internals/cyphers/feistel.h"
#include "internals/cyphers/stream.h"

#define PORT 8080

/* Safe strdup */
static char* safe_strdup(const char* s)
{
    if (!s) return NULL;
    char* r = malloc(strlen(s) + 1);
    if (r) strcpy(r, s);
    return r;
}

/* Send response with CORS headers */
static int send_response(struct MHD_Connection *connection, const char *text, int status)
{
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(text), (void*)text, MHD_RESPMEM_MUST_COPY);

    MHD_add_response_header(response, "Content-Type", "text/plain; charset=utf-8");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");

    int ret = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return ret;
}

/* Handle incoming requests */
static int handle_request(
    void *cls,
    struct MHD_Connection *connection,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls)
{
    (void)cls; (void)version; (void)upload_data;
    (void)upload_data_size; (void)con_cls;

    /* Handle CORS preflight */
    if (strcmp(method, "OPTIONS") == 0)
    {
        return send_response(connection, "", MHD_HTTP_OK);
    }

    if (strcmp(method, "GET") != 0)
        return send_response(connection, "Only GET/OPTIONS supported\n", MHD_HTTP_METHOD_NOT_ALLOWED);

    /* Extract query parameters */
    const char *alph   = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "alph");
    const char *cipher = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "cipher");
    const char *frag   = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "frag");

    char *alph_c   = safe_strdup(alph);
    char *cipher_c = safe_strdup(cipher);
    char *frag_c   = safe_strdup(frag);

    if (!cipher_c || !frag_c)
    {
        free(alph_c); free(cipher_c); free(frag_c);
        return send_response(connection, "ERROR: missing cipher or frag\n", MHD_HTTP_BAD_REQUEST);
    }

    const char *result = NULL;

    /* Routing */
    if (strcmp(url, "/rabin") == 0)
        result = rabinEntry(alph_c, cipher_c, frag_c);
    else if (strcmp(url, "/rsa") == 0)
        result = rsaEntry(alph_c, cipher_c, frag_c);
    else if (strcmp(url, "/enigma") == 0)
        result = enigmaEntry(alph_c, cipher_c, frag_c);
    else if (strcmp(url, "/shamir") == 0)
        result = shamirEntryMem(alph_c, cipher_c, frag_c);
    else if (strcmp(url, "/stream") == 0)
        result = streamEntry(alph_c, cipher_c, frag_c);
    else
    {
        free(alph_c); free(cipher_c); free(frag_c);
        return send_response(connection, "404 Not Found\n", MHD_HTTP_NOT_FOUND);
    }

    int ret = send_response(connection, result, MHD_HTTP_OK);

    /* Clean up */
    free((void*)result);
    free(alph_c); free(cipher_c); free(frag_c);

    return ret;
}

int main()
{
    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY,
        PORT,
        NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_END);

    if (!daemon)
    {
        printf("Failed to start server\n");
        return 1;
    }

    printf("Server running at http://localhost:%d\n", PORT);
    printf("Endpoints:\n  /rabin\n  /rsa\n  /enigma\n  /shamir\n  /stream\n\nPress ENTER to stop.\n");

    getchar();
    MHD_stop_daemon(daemon);
    return 0;
}