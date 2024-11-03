#pragma once

#define SHA_DIGEST_LENGTH 20

#include <stdint.h>

/// Calculates the SHA256 hash of the given null-terminated string in `data`
/// into `result`.
///
/// `data_length` should be the length in bytes of the data, e.g. using
/// `strlen`.
void sha1(const char* data, int data_length, char result[SHA_DIGEST_LENGTH]);

struct sha1_ctx {
  uint32_t H[5];
  uint32_t count[2];
  unsigned char buffer[64];
};

void sha1_init(struct sha1_ctx* ctx);
void sha1_update(struct sha1_ctx* ctx, unsigned const char* data,
                 uint32_t data_length);
void sha1_final(struct sha1_ctx* ctx, unsigned char* result);