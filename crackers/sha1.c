// Based on: https://github.com/CTrabant/teeny-sha1/blob/main/teeny-sha1.c

#include "sha1.h"

#include <stdint.h>
#include <string.h>

#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

void sha1(const char *data, int data_length, char result[SHA1_LENGTH]) {
  uint32_t W[80];
  uint32_t H[] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f = 0;
  uint32_t k = 0;

  uint32_t idx;
  uint32_t lidx;
  uint32_t widx;
  uint32_t didx = 0;

  int32_t wcount;
  uint32_t temp;
  uint64_t databits = ((uint64_t)data_length) * 8;
  uint32_t loopcount = (data_length + 8) / 64 + 1;
  uint32_t tailbytes = 64 * loopcount - data_length;
  uint8_t datatail[128] = {0};

  /* Pre-processing of data tail (includes padding to fill out 512-bit chunk):
     Add bit '1' to end of message (big-endian)
     Add 64-bit message length in bits at very end (big-endian) */
  datatail[0] = 0x80;
  datatail[tailbytes - 8] = (uint8_t)(databits >> 56 & 0xFF);
  datatail[tailbytes - 7] = (uint8_t)(databits >> 48 & 0xFF);
  datatail[tailbytes - 6] = (uint8_t)(databits >> 40 & 0xFF);
  datatail[tailbytes - 5] = (uint8_t)(databits >> 32 & 0xFF);
  datatail[tailbytes - 4] = (uint8_t)(databits >> 24 & 0xFF);
  datatail[tailbytes - 3] = (uint8_t)(databits >> 16 & 0xFF);
  datatail[tailbytes - 2] = (uint8_t)(databits >> 8 & 0xFF);
  datatail[tailbytes - 1] = (uint8_t)(databits >> 0 & 0xFF);

  /* Process each 512-bit chunk */
  for (lidx = 0; lidx < loopcount; lidx++) {
    /* Compute all elements in W */
    memset(W, 0, 80 * sizeof(uint32_t));

    /* Break 512-bit chunk into sixteen 32-bit, big endian words */
    for (widx = 0; widx <= 15; widx++) {
      wcount = 24;

      /* Copy byte-per byte from specified buffer */
      while (didx < data_length && wcount >= 0) {
        W[widx] += (((uint32_t)data[didx]) << wcount);
        didx++;
        wcount -= 8;
      }
      /* Fill out W with padding as needed */
      while (wcount >= 0) {
        W[widx] += (((uint32_t)datatail[didx - data_length]) << wcount);
        didx++;
        wcount -= 8;
      }
    }

    /* Extend the sixteen 32-bit words into eighty 32-bit words, with potential
       optimization from: "Improving the Performance of the Secure Hash
       Algorithm (SHA-1)" by Max Locktyukhin */
    for (widx = 16; widx <= 31; widx++) {
      W[widx] =
          ROTLEFT((W[widx - 3] ^ W[widx - 8] ^ W[widx - 14] ^ W[widx - 16]), 1);
    }
    for (widx = 32; widx <= 79; widx++) {
      W[widx] = ROTLEFT(
          (W[widx - 6] ^ W[widx - 16] ^ W[widx - 28] ^ W[widx - 32]), 2);
    }

    /* Main loop */
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    for (idx = 0; idx <= 79; idx++) {
      if (idx <= 19) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      } else if (idx >= 20 && idx <= 39) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (idx >= 40 && idx <= 59) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else if (idx >= 60 && idx <= 79) {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      temp = ROTLEFT(a, 5) + f + e + k + W[idx];
      e = d;
      d = c;
      c = ROTLEFT(b, 30);
      b = a;
      a = temp;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
  }

  /* Store binary digest in supplied buffer */
  for (int i = 0; i < 5; i++) {
    result[i * 4 + 0] = (uint8_t)(H[i] >> 24);
    result[i * 4 + 1] = (uint8_t)(H[i] >> 16);
    result[i * 4 + 2] = (uint8_t)(H[i] >> 8);
    result[i * 4 + 3] = (uint8_t)(H[i]);
  }
}

void sha1_init(struct sha1_ctx* ctx) {
    *ctx = (struct sha1_ctx){
        {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0},
        0,
        { 0 },
        0,
    };
}

static void sha1_feed_block(struct sha1_ctx* ctx, const char* block) {
    uint32_t W[80] = { 0 };
    uint32_t idx;
    uint32_t widx = 0;
    uint32_t didx = 0;
    int32_t wcount;
    uint32_t temp;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f = 0;
    uint32_t k = 0;

    /* Break 512-bit chunk into sixteen 32-bit, big endian words */
    for (widx = 0; widx <= 15; widx++) {
        /* Copy byte-per byte from specified buffer */
        for (wcount = 24; wcount >= 0; wcount -= 8) {
            W[widx] += (((uint32_t)(block[didx] & 0xFF)) << wcount);
            didx++;
        }
    }
    /* Extend the sixteen 32-bit words into eighty 32-bit words, with potential
       optimization from: "Improving the Performance of the Secure Hash
       Algorithm (SHA-1)" by Max Locktyukhin */
    for (widx = 16; widx <= 31; widx++) {
        W[widx] = ROTLEFT((W[widx - 3] ^ W[widx - 8] ^ W[widx - 14] ^ W[widx - 16]), 1);
    }
    for (widx = 32; widx <= 79; widx++) {
        W[widx] = ROTLEFT((W[widx - 6] ^ W[widx - 16] ^ W[widx - 28] ^ W[widx - 32]), 2);
    }

    /* Main loop */
    a = ctx->H[0];
    b = ctx->H[1];
    c = ctx->H[2];
    d = ctx->H[3];
    e = ctx->H[4];

    for (idx = 0; idx < 80; idx++) {
        if (idx <= 19) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (idx >= 20 && idx <= 39) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (idx >= 40 && idx <= 59) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else if (idx >= 60 && idx <= 79) {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        temp = ROTLEFT(a, 5) + f + e + k + W[idx];
        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = temp;
    }

    ctx->H[0] += a;
    ctx->H[1] += b;
    ctx->H[2] += c;
    ctx->H[3] += d;
    ctx->H[4] += e;
}

void sha1_update(struct sha1_ctx* ctx, const char* data, uint32_t data_length) {
    ctx->size += data_length * 8; /* size in bits */
    /* Not enogth data */
    if (ctx->buffer_size + data_length < 64) {
        memcpy(ctx->buffer + ctx->buffer_size, data, data_length);
        ctx->buffer_size += data_length;
        return;
    }
    /* ctx->buffer is not empty */
    if (ctx->buffer_size > 0) {
        memcpy(ctx->buffer + ctx->buffer_size, data, 64 - ctx->buffer_size);
        sha1_feed_block(ctx, ctx->buffer);
        data += ctx->buffer_size;
        data_length -= ctx->buffer_size;
        ctx->buffer_size = 0;
    }
    /* Feed middle blocks */
    for (; data_length >= 64; data_length -= 64) {
        sha1_feed_block(ctx, data);
        data += 64;
    }
    /* Store reminder of data */
    if (data_length > 0) {
        memcpy(ctx->buffer, data, data_length);
        ctx->buffer_size = data_length;
    }
}

void sha1_final(struct sha1_ctx* ctx, char* result) {
    ctx->buffer[ctx->buffer_size] = 0x80;
    ctx->buffer_size += 1;

    if (ctx->buffer_size > 64 - 8) {
        memset(ctx->buffer + ctx->buffer_size, 0, 64 - ctx->buffer_size);
        sha1_feed_block(ctx, ctx->buffer);
        ctx->buffer_size = 0;
    }
    /* Last block */
    memset(ctx->buffer + ctx->buffer_size, 0, 64 - 8 - ctx->buffer_size);
    ctx->buffer[64 - 8] = (uint8_t)((ctx->size >> 56) & 0xFF);
    ctx->buffer[64 - 7] = (uint8_t)((ctx->size >> 48) & 0xFF);
    ctx->buffer[64 - 6] = (uint8_t)((ctx->size >> 40) & 0xFF);
    ctx->buffer[64 - 5] = (uint8_t)((ctx->size >> 32) & 0xFF);
    ctx->buffer[64 - 4] = (uint8_t)((ctx->size >> 24) & 0xFF);
    ctx->buffer[64 - 3] = (uint8_t)((ctx->size >> 16) & 0xFF);
    ctx->buffer[64 - 2] = (uint8_t)((ctx->size >> 8) & 0xFF);
    ctx->buffer[64 - 1] = (uint8_t)((ctx->size >> 0) & 0xFF);

    sha1_feed_block(ctx, ctx->buffer);

    /* Store binary digest in supplied buffer */
    for (int i = 0; i < 5; i++) {
        result[i * 4 + 0] = (uint8_t)((ctx->H[i] >> 24) & 0xFF);
        result[i * 4 + 1] = (uint8_t)((ctx->H[i] >> 16) & 0xFF);
        result[i * 4 + 2] = (uint8_t)((ctx->H[i] >> 8) & 0xFF);
        result[i * 4 + 3] = (uint8_t)((ctx->H[i]) & 0xFF);
    }
}