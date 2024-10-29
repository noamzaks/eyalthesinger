#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>

#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$&*"
#define CHARSET_SIZE (sizeof(CHARSET) - 1)
#define MAX_PASS_LEN 64

char target_hash[SHA256_LENGTH] = {0xae, 0xaf, 0xd1, 0x7e, 0xac, 0xad, 0xe7, 0x13, 0xe6, 0xe9, 0xb3, 0xa4, 0xa9, 0xe7, 0x45, 0xfb, 0xba, 0x7e, 0xf5, 0xa1, 0x5d, 0x34, 0xb8, 0x84, 0x28, 0xae, 0xa9, 0xa1, 0x9f, 0x62, 0x9d, 0x9a};


int compare_hash(const char *target_hash, char *hash_to_check) {
    int i;
    for (i = 0; i < SHA256_LENGTH; i++) {
        if (target_hash[i] != hash_to_check[i]) {
            return 0;
        }
    }

    return 1;
}


void brute_force_for_length(const char *target_hash, int curr_length, char *buffer, int *found) {
    int length, j;
    unsigned long i;
    char hash_calc[SHA256_LENGTH];

    // Null-terminate the buffer at the desired length
    buffer[curr_length] = '\0';

    // Generate combinations
    for (length = 1; length <= curr_length; length++) {
        for (i = 0; i < (unsigned long) pow(CHARSET_SIZE, length); i++) {
            // Build the string for the current combination
            for (j = 0; j < length; j++) {
                buffer[j] = CHARSET[(i / (unsigned long) pow(CHARSET_SIZE, j)) % CHARSET_SIZE];
            }
            
            sha256(target_hash, hash_calc);
            if (compare_hash(target_hash, hash_calc)) {
                *found = 1;
                return;
            }

        }
    }
}


void brute_force(const char *target_hash) {
    int i, found;
    char *buffer = malloc(MAX_PASS_LEN);

    if (!buffer) {
        perror("Error in malloc\n");
        return;
    }

    found = 0;

    for (i = 0; i < MAX_PASS_LEN; i++) {
        brute_force_for_length(target_hash, i, buffer, &found);
        if (found) {
            printf("found password!\nThe password is: %s\n", buffer);
            free(buffer);
            return;
        }
    }

    perror("Couldn't find password\n");
    free(buffer);
}


int main() {
    brute_force(target_hash);

    return 0;
}
