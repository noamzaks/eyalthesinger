#pragma once

#define MIC_LENGTH 16
#define MAC_LENGTH 6
#define NONCE_LENGTH 32

/// Calculates the MIC of the given WPA 4-way handshake into `result`.
void mic(const char *password, int password_length, const char *ssid,
         const char client_mac[MAC_LENGTH], const char server_mac[MAC_LENGTH],
         const char client_nonce[NONCE_LENGTH],
         const char server_nonce[NONCE_LENGTH], const char *second_packet,
         int second_packet_length, char result[MIC_LENGTH]);
