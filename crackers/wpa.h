#pragma once

// length constants, all in bytes!
#define MIC_LENGTH 16
#define MAC_LENGTH 6
#define NONCE_LENGTH 32
#define SALT_LENGTH 2 * MAC_LENGTH + 2 * NONCE_LENGTH
#define PMK_LENGTH 32
#define KCK_LENGTH 16
#define HMAC_SHA1_ITER 4096


#define EMPTY_MIC                                                              \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


/* constant salt used in the algorithm ('A') */
#define CONST_A_SALT "Pairwise key expansion"
#define CONST_A_SALT_LENGTH strlen("Pairwise key expansion")

/// Calculates the MIC of the given WPA 4-way handshake into `result`.
void mic(const char *password, int password_length, const char *ssid,
         const char client_mac[MAC_LENGTH], const char server_mac[MAC_LENGTH],
         const char client_nonce[NONCE_LENGTH],
         const char server_nonce[NONCE_LENGTH], const char *second_packet_eapol,
         int second_packet_eapol_length, char result[MIC_LENGTH]);
