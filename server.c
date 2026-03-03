#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>

#include "internals/cyphers/rabin.h"

#define PORT_DEFAULT 8080

static int handle_request(
    void *cls,
    struct MHD_Connection *connection,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls
) {
    (void)cls; (void)version; (void)upload_data;
    (void)upload_data_size; (void)con_cls;

    if (strcmp(method, "GET") != 0) {
        return MHD_NO;
    }

    if (strcmp(url, "/rabin") != 0) {
        const char *msg = "404 Not Found\n";
        struct MHD_Response *res =
            MHD_create_response_from_buffer(
                strlen(msg),
                (void*)msg,
                MHD_RESPMEM_PERSISTENT
            );
        int ret = MHD_queue_response(connection, 404, res);
        MHD_destroy_response(res);
        return ret;
    }

    const char *alph   = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "alph");
    const char *cipher = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "cipher");
    const char *frag   = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "frag");

    if (!cipher || !frag) {
        const char *msg = "ERROR: missing cipher or frag\n";
        struct MHD_Response *res =
            MHD_create_response_from_buffer(
                strlen(msg),
                (void*)msg,
                MHD_RESPMEM_PERSISTENT
            );
        int ret = MHD_queue_response(connection, 400, res);
        MHD_destroy_response(res);
        return ret;
    }

    const char *result = rabinEntry(alph, cipher, frag);

    struct MHD_Response *response =
        MHD_create_response_from_buffer(
            strlen(result),
            (void*)result,
            MHD_RESPMEM_MUST_COPY
        );

    MHD_add_response_header(response, "Content-Type", "text/plain; charset=utf-8");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");

    int ret = MHD_queue_response(connection, 200, response);
    MHD_destroy_response(response);
    free((void*)result);

    return ret;
}

int main(int argc, char **argv) {
    int port = PORT_DEFAULT;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0) port = PORT_DEFAULT;
    }

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY,
        port,
        NULL,
        NULL,
        &handle_request,
        NULL,
        MHD_OPTION_END
    );

    if (!daemon) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    printf("Sabaton server running on http://localhost:%d\n", port);
    printf("Endpoint: /rabin\n");
    printf("Press ENTER to stop.\n");

    getchar();

    MHD_stop_daemon(daemon);
    return 0;
}
//gcc ./server.c ./internals/hash.c ./internals/cyphers/affineCaesar.c ./internals/cyphers/enigma.c ./internals/cyphers/aes.c ./internals/cyphers/feistel.c ./internals/cyphers/block.c ./internals/cyphers/hill.c ./internals/cyphers/scytale.c ./internals/cyphers/transposition.c ./internals/cyphers/vigenere.c ./internals/hashes/crc32.c ./internals/hashes/murmur3.c ./internals/hashes/sha1.c ./internals/hashes/sha256.c ./internals/hashes/xxhash32.c ./internals/enhancements/lith/lithuanian.c ./internals/cyphers/bifid.c ./internals/cyphers/fleissner.c ./internals/cyphers/stream.c ./internals/cyphers/knapsack.c ./internals/cyphers/merkle.c ./internals/cyphers/graham.c ./internals/cyphers/rsa.c ./util/bigint.c ./internals/cyphers/elgamal.c ./internals/cyphers/elliptic.c ./internals/cyphers/rabin.c ./internals/cyphers/zkp.c ./internals/cyphers/shamir.c ./internals/cyphers/asmuth.c ./internals/cyphers/a5.c -lmicrohttpd -o sabaton_server