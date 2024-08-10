#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crackers/sha1.h"
#include "crackers/hmac.h"
#include "crackers/pbkdf2.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s [sha1 | pkdf] <args...>\n", argv[0]);
        return 1;
    }

    const char* mode = argv[1];

    if (strcmp(mode, "sha1") == 0) {
        if (argc != 3) {
            fprintf(stderr, "usage: %s sha1 <message>\n", argv[0]);
            return 1;
        }
        const char* data = argv[2];
        char result[20];
        char hexresult[41] = { 0 };
        struct sha1_ctx ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, data, strlen(data));
        sha1_final(&ctx, result);
        for (int i = 0; i < sizeof(result); ++i) {
            sprintf(hexresult + 2*i, "%02x", result[i] & 0xFF);
        }
        printf("%s\n", hexresult);
    } else if (strcmp(mode, "hmac_sha1") == 0) {
        if (argc != 4) {
            fprintf(stderr, "usage: %s hmac_sha1 <key> <message>\n", argv[0]);
            return 1;
        }
        const char* key = argv[2];
        const char* message = argv[3];
        char result[20];
        char hexresult[41] = { 0 };
        hmac_sha1(message, strlen(message), key, strlen(key), result);
        for (int i = 0; i < sizeof(result); ++i) {
            sprintf(hexresult + 2*i, "%02x", result[i] & 0xFF);
        }
        printf("%s\n", hexresult);
    } else if (strcmp(mode, "pbkdf2_sha1") == 0) {
        if (argc != 6) {
            fprintf(stderr, "usage: %s pbkdf2_sha1 <password> <salt> <iteration> <dkLen>\n", argv[0]);
            return 1;
        }
        const char* password = argv[2];
        const char* salt = argv[3];
        int iteration = atoi(argv[4]);
        int dkLen = atoi(argv[5]);
        char result[1024] = { 0 };
        char hexresult[sizeof(result)*2+1] = { 0 };

        pbkdf2_sha1(password, strlen(password), salt, strlen(salt), iteration, dkLen, result);

        for (int i = 0; i < dkLen; ++i) {
            sprintf(hexresult + 2*i, "%02x", result[i] & 0xFF);
        }
        printf("%s\n", hexresult);
    } else {
        fprintf(stderr, "usage: %s [sha1 | pkdf] <args...>\n", argv[0]);
        return 1;
    }

    return 0;
}