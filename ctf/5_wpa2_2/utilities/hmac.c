#include "hmac.h"

#include <string.h>

#include "sha1.h"

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void hmac_sha1(const char *text,  /* pointer to data stream */
               uint32_t text_len, /* length of data stream */
               const char *key,   /* pointer to authentication key */
               uint32_t key_len,  /* length of authentication key */
               char *digest       /* caller digest to be filled in */
) {
  struct sha1_ctx context;
  char k_ipad[64]; /* inner padding - key XORd with ipad */
  char k_opad[64]; /* outer padding - key XORd with opad */
  char tk[20] = {0};
  int i;
  /* if key is longer than 64 bytes reset it to key=SHA1(key) */
  if (key_len > 64) {
    sha1(key, key_len, tk);
    key = tk;
    key_len = 20;
  }

  memset(k_ipad, 0, sizeof k_ipad);
  memset(k_opad, 0, sizeof k_opad);
  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);

  for (i = 0; i < 64; i++) {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  sha1_init(&context);                   /* init context for 1st pass */
  sha1_update(&context, k_ipad, 64);     /* start with inner pad */
  sha1_update(&context, text, text_len); /* then text of datagram */
  sha1_final(&context, digest);          /* finish up 1st pass */
  /*
   * perform outer SHA1
   */
  sha1_init(&context);               /* init context for 2nd pass */
  sha1_update(&context, k_opad, 64); /* start with outer pad */
  sha1_update(&context, digest, 20); /* then results of 1st hash */
  sha1_final(&context, digest);      /* finish up 2nd pass */
}
