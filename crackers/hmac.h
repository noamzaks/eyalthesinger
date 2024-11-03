#pragma once

#include <stdint.h>

void hmac_sha1_prepare_key(const char* key, uint32_t key_len,
                           unsigned char k_ipad[64], unsigned char k_opad[64]);
void hmac_sha1_inner(const char* text, uint32_t text_len,
                     const unsigned char k_ipad[64],
                     const unsigned char k_opad[64], char* digest);

void hmac_sha1(const char* text, uint32_t text_len, const char* key,
               uint32_t key_len, char* digest);