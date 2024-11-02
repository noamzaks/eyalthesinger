#pragma once

#include <stdint.h>

#define SHA256_LENGTH 32

/// Calculates the SHA256 hash of the given null-terminated string in `data`
/// into `result`.
void sha256(const char *data, char result[SHA256_LENGTH]);
