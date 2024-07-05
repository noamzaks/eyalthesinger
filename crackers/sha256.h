#pragma once

/// A SHA256 brute-force cracker.

#include <stdbool.h>
#include <stdint.h>

/// Checks whether the current password hashes to the given result. Assumes the
/// result's length is 32B, like SHA256 hashes.
bool sha256_check(const char *password, const char *result);
