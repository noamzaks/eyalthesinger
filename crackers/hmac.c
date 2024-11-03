#include "hmac.h"

#include <string.h>

#include "sha1.h"

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void hmac_sha1(const char* text, uint32_t text_len, const char* key,
               uint32_t key_len, char* digest) {
  unsigned char k_ipad[64];
  unsigned char k_opad[64];

  hmac_sha1_prepare_key(key, key_len, k_ipad, k_opad);
  hmac_sha1_inner(text, text_len, k_ipad, k_opad, digest);
}

void hmac_sha1_prepare_key(const char* key, /* pointer to authentication key */
                           uint32_t key_len /* length of authentication key */,
                           unsigned char k_ipad[64], unsigned char k_opad[64]) {
  char tk[20] = {0};
  int i;
  /* if key is longer than 64 bytes reset it to key=SHA1(key) */
  if (key_len > 64) {
    sha1(key, key_len, tk);
    key = tk;
    key_len = 20;
  }

  memset(k_ipad, 0x36, 64);
  memset(k_opad, 0x5c, 64);

  for (i = 0; i < key_len; i++) {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }
}

void hmac_sha1_inner(const char* text, uint32_t text_len,
                     const unsigned char k_ipad[64],
                     const unsigned char k_opad[64], char* digest) {
  struct sha1_ctx context;

  sha1_init(&context);                   /* init context for 1st pass */
  sha1_update(&context, k_ipad, 64);     /* start with inner pad */
  sha1_update(&context, text, text_len); /* then text of datagram */
  sha1_final(&context, digest);          /* finish up 1st pass */

  sha1_init(&context);               /* init context for 2nd pass */
  sha1_update(&context, k_opad, 64); /* start with outer pad */
  sha1_update(&context, digest, 20); /* then results of 1st hash */
  sha1_final(&context, digest);      /* finish up 2nd pass */
}
