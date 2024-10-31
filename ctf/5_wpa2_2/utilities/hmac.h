#pragma once

#include <stdint.h>

void hmac_sha1(const char *text, uint32_t text_len, const char* key, uint32_t key_len, char* digest);