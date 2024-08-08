#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crackers/sha1.h"




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
    } else {
        fprintf(stderr, "usage: %s [sha1 | pkdf] <args...>\n", argv[0]);
        return 1;
    }

    return 0;
}