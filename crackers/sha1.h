#pragma once

#define SHA1_LENGTH 20

#include <stdint.h>

/// Calculates the SHA256 hash of the given null-terminated string in `data`
/// into `result`.
///
/// `data_length` should be the length in bytes of the data, e.g. using
/// `strlen`.
void sha1(const char *data, int data_length, char result[SHA1_LENGTH]);
