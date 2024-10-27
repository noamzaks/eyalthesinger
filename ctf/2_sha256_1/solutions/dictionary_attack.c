#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFF_LEN 256

char target_hash[SHA256_LENGTH] = {0x47, 0x2f, 0xd7, 0x5d, 0x4a, 0x10, 0xce, 0x85, 0x66, 0x36, 0x19, 0x1c, 0xa9, 0xce, 0x79, 0xea, 0x33, 0x1e, 0x90, 0x6b, 0xa2, 0x31, 0xa5, 0x4e, 0xef, 0x53, 0x9a, 0x10, 0x32, 0x61, 0x99, 0x13};
int target = 4711203;

int compare_hash (const char *target_hash, char *hash_to_check) {
    int i;
    for (i = 0; i < SHA256_LENGTH; i++) {
        if (target_hash[i] != hash_to_check[i]) {
            return 0;
        }
    }

    return 1;
}


void find_password(const char *target_hash, FILE* file) {
    int read;
    char *buffer;
    char hash_calc[SHA256_LENGTH];
    int buff_len = BUFF_LEN;
    
    buffer = (char *)malloc(BUFF_LEN * sizeof(char));

    if (!buffer) {
        printf("Error in malloc\n");
        return;
    }

    while (read = getline(&buffer, &buff_len, file) != -1) {
        buffer[strcspn(buffer, "\r\n")] = '\0';
        sha256(buffer, hash_calc);
        if (compare_hash(target_hash, hash_calc)) {
            printf("found password!\nThe password is: %s\n", buffer);
            free(buffer);
            return;
        }
    }

    printf("Couldn't find password\n");
    free(buffer);
}


int main() {
    FILE *file = fopen("rockyou.txt", "r");
    if (file == NULL) {
        printf("Error: Could not open password file.\n");
        return 1;
    }

    find_password(target_hash, file);

    fclose(file);

    return 0;
}