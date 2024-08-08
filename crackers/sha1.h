#pragma once

#define SHA1_LENGTH 20

#include <stdint.h>

/// Calculates the SHA256 hash of the given null-terminated string in `data`
/// into `result`.
///
/// `data_length` should be the length in bytes of the data, e.g. using
/// `strlen`.
void sha1(const char *data, int data_length, char result[SHA1_LENGTH]);

struct sha1_ctx {
    uint32_t H[5];
    uint64_t size;
    char buffer[64];
    char buffer_size;
};

void sha1_init(struct sha1_ctx* ctx);
void sha1_update(struct sha1_ctx* ctx, const char* data, uint32_t data_length);
void sha1_final(struct sha1_ctx* ctx, char* result);