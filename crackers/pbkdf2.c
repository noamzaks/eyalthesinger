#include "pbkdf2.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>

#include "hmac.h"
#include "sha1.h"

#define MAX_SALT_LENGTH 4096

static void xor_bytes(char* dst, char* src, unsigned int length) {
  for (int i = 0; i < length; ++i) {
    dst[i] ^= src[i];
  }
}

void pbkdf2_sha1(const char* password, int password_length, const char* salt,
                 int salt_length, uint32_t iterations, int dkLen,
                 char* output) {
  const uint32_t hLen = SHA_DIGEST_LENGTH;
  char U[MAX_SALT_LENGTH + 4];
  char T[SHA_DIGEST_LENGTH];
  int U_length = 0;

  // assert (dkLen <= ((1 << 32) - 1) * hLen); /* derived key too long */

  for (unsigned int i = 1; i <= (dkLen - 1) / SHA_DIGEST_LENGTH +
                                    1 /* ceil(dkLen/SHA_DIGEST_LENGTH) */;
       ++i) {
    memset(U, 0, sizeof(U));
    memset(T, 0, sizeof(T));
    /* U_0 */
    memcpy(U, salt, salt_length);
    U[salt_length] = ((i >> 24) & 0xFF);
    U[salt_length + 1] = ((i >> 16) & 0xFF);
    U[salt_length + 2] = ((i >> 8) & 0xFF);
    U[salt_length + 3] = (i & 0xFF);
    U_length = salt_length + 4;

    unsigned char k_ipad[64];
    unsigned char k_opad[64];
    hmac_sha1_prepare_key(password, password_length, k_ipad, k_opad);

    // struct sha1_ctx inner, outer;
    // sha1_init(&inner);
    // sha1_update(&inner, k_ipad, 64);
    // sha1_init(&outer);
    // sha1_update(&outer, k_opad, 64);

    SHA_CTX inner, outer;
    SHA1_Init(&inner);
    SHA1_Update(&inner, k_ipad, 64);
    SHA1_Init(&outer);
    SHA1_Update(&outer, k_opad, 64);

    for (int j = 1; j <= iterations; ++j) {
      // struct sha1_ctx context = inner;
      // sha1_update(&context, U, U_length);
      // sha1_final(&context, U);
      // context = outer;
      // sha1_update(&context, U, 20);
      // sha1_final(&context, U);

      SHA_CTX context = inner;
      SHA1_Update(&context, U, U_length);
      SHA1_Final(U, &context);
      context = outer;
      SHA1_Update(&context, U, 20);
      SHA1_Final(U, &context);

      // SHA_CTX context;
      // SHA1_Init(&context);
      // SHA1_Update(&context, k_ipad, 64);
      // SHA1_Update(&context, U, U_length);
      // SHA1_Final(U, &context);
      // SHA1_Init(&context);
      // SHA1_Update(&context, k_opad, 64);
      // SHA1_Update(&context, U, 20);
      // SHA1_Final(U, &context);

      U_length = SHA_DIGEST_LENGTH;
      xor_bytes(T, U, SHA_DIGEST_LENGTH);
    }

    if (i < (dkLen - 1) / SHA_DIGEST_LENGTH + 1) {
      memcpy(output + SHA_DIGEST_LENGTH * (i - 1), T, SHA_DIGEST_LENGTH);
    } else {
      memcpy(output + SHA_DIGEST_LENGTH * (i - 1), T,
             (dkLen - 1) % SHA_DIGEST_LENGTH + 1);
    }
  }
}