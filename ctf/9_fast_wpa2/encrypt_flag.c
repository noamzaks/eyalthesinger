
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>



void encrypt(const unsigned char *key, const unsigned char *plaintext, unsigned char *ciphertext) {
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 128, &enc_key); // 128-bit key
    AES_encrypt(plaintext, ciphertext, &enc_key);
}

int main() {
    const char *flag = "D00f3nshm!rtz";
    unsigned char key[16] = {0xdd, 0x05, 0x24, 0x81, 0xb9, 0x96, 0xa7, 0xd8, 0x89, 0xd8, 0x8b, 0xcb, 0xe7, 0x9a, 0x69, 0x78};
    unsigned char ciphertext[AES_BLOCK_SIZE];

    // Pad plaintext to the block size
    unsigned char plaintext[AES_BLOCK_SIZE];
    memset(plaintext, 0, AES_BLOCK_SIZE);
    strncpy((char *)plaintext, flag, AES_BLOCK_SIZE);

    encrypt(key, plaintext, ciphertext);

    // Output the encrypted flag as hex
    printf("Encrypted flag: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("0x%02x, ", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
