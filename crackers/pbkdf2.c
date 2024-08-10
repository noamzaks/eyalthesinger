#include "pbkdf2.h"

#include <string.h>

#include <stdio.h>
#include "hmac.h"
#include "sha1.h"

#define MAX_SALT_LENGTH 4096

static void xor(char *dst, char* src, unsigned int length) {
    for (int i = 0; i < length; ++i) {
        dst[i] ^= src[i];
    }
}

void pbkdf2_sha1(const char* password, int password_length, const char* salt, int salt_length, uint32_t iterations, int dkLen, char* output) {
    const uint32_t hLen = SHA1_LENGTH;
    char U[MAX_SALT_LENGTH+4];
    char T[SHA1_LENGTH];
    int U_length = 0;

    // assert (dkLen <= ((1 << 32) - 1) * hLen); /* derived key too long */

    for (unsigned int i = 1; i <= (dkLen-1) / SHA1_LENGTH + 1 /* ceil(dkLen/SHA1_LENGTH) */; ++i) {
        memset(U, 0, sizeof(U));
        memset(T, 0, sizeof(T));
        /* U_0 */
        memcpy(U, salt, salt_length);
        U[salt_length] = ((i >> 24) & 0xFF);
        U[salt_length+1] = ((i >> 16) & 0xFF);
        U[salt_length+2] = ((i >> 8) & 0xFF);
        U[salt_length+3] = (i & 0xFF);
        U_length = salt_length + 4;

        for (int j = 1; j <= iterations; ++j) {
            hmac_sha1(U, U_length, password, password_length, U);
            U_length = SHA1_LENGTH;
            xor(T, U, SHA1_LENGTH);
        }

        if (i < (dkLen-1) / SHA1_LENGTH + 1) {
            memcpy(output + SHA1_LENGTH * (i-1), T, SHA1_LENGTH);
        } else {
            memcpy(output + SHA1_LENGTH * (i-1), T, (dkLen-1) % SHA1_LENGTH + 1);
        }
    }
}