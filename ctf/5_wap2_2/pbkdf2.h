#pragma once

#include <stdint.h>

void pbkdf2_sha1(const char* password, int password_length, const char* salt, int salt_length, uint32_t iterations, int dkLen, char* output);
