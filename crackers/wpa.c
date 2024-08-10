#include "wpa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crackers/sha1.h"
#include "crackers/sha256.h"
#include "crackers/hmac.h"
#include "crackers/pbkdf2.h"

// JUST FOR TESTING! remove later
// #define PASS_PHRASE "123456789"
// #define SSID "Building_G2"
// #define AP_MAC "\x28\xb3\x71\x20\xf2\x2c"
// #define CLIENT_MAC "\x20\xc1\x9b\x58\xd6\xa3"
// #define client_nonce
// "\x58\x35\xa6\x01\xdf\x74\x1d\xcf\x5f\x50\x49\x5b\xa7\x0d\xd8\x74\x5a\x73\x9e\x67\x70\xe0\xda\xf8\xcc\xda\x88\x01\x00\x09\xc2\x71"
// #define server_nonce
// "\x3f\x04\x5e\x6b\x81\xf5\x6f\x7c\xeb\xbb\xdb\xb9\xdb\xfb\x62\xb3\xdb\x8a\x39\x2c\x33\x99\x62\xb1\xb5\xa3\xad\xdf\xc2\xe3\x97\xb0"
// #define DATA "\x01\x03\x00_\xfe\x01\t\x00
// \x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define EMPTY_MIC                                                              \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
// #define EAPOL_LEN 121

// length constants
#define MIC_LEN 16
#define MAC_LEN 6
#define NONCE_LEN 32
#define SALT_LEN 2 * MAC_LEN + 2 * NONCE_LEN
#define PMK_LEN 32
#define PTK_LEN 64
#define HMAC_SHA1_ITER 4096

/* constant salt used in the algorithm ('A') */
#define CONST_A_SALT "Pairwise key expansion"
#define CONST_A_SALT_LEN strlen("Pairwise key expansion")

void calc_dynamic_B_salt(const char *client_mac, const char *server_mac, const char *client_nonce,
                         const char *server_nonce, char *dynamic_B_salt) {
  /**
   * calculates the dynamic salt used in the algorithm ('B')
   * the calculation performed is:
   * B = min(server_mac, client_mac) || max(server_mac, client_mac) ||
   * min(client_nonce, server_nonce) || max(client_nonce, server_nonce)
   *
   * @param client_mac: the client's mac address
   * @param server_mac: the server's mac address
   * @param client_nonce: client nonce
   * @param server_nonce: server nonce
   * @param dynamic_B_salt: pointer to a buffer to output the B salt in
   *
   */

  /* zero buffer before use */
  memset(dynamic_B_salt, 0, SALT_LEN);

  /* min(server_mac, client_mac) || max(server_mac, client_mac) */
  if (memcmp(client_mac, server_mac, MAC_LEN) <= 0) {
    memcpy(dynamic_B_salt, client_mac, MAC_LEN);
    memcpy(dynamic_B_salt + MAC_LEN, server_mac, MAC_LEN);
  } else {
    memcpy(dynamic_B_salt, server_mac, MAC_LEN);
    memcpy(dynamic_B_salt + MAC_LEN, client_mac, MAC_LEN);
  }

  /* min(client_nonce, server_nonce) || max(client_nonce, server_nonce) */

  if (memcmp(client_nonce, server_nonce, NONCE_LEN) <= 0) {
    memcpy(dynamic_B_salt + 2 * MAC_LEN, client_nonce, NONCE_LEN);
    memcpy(dynamic_B_salt + 2 * MAC_LEN + NONCE_LEN, server_nonce, NONCE_LEN);
  } else {
    memcpy(dynamic_B_salt + 2 * MAC_LEN, server_nonce, NONCE_LEN);
    memcpy(dynamic_B_salt + 2 * MAC_LEN + NONCE_LEN, client_nonce, NONCE_LEN);
  }
}

void calc_ptk_by_custom_PRF512(const char *pmk,
                               const char *dynamic_B_salt,
                               char *ptk) {
  /**
   * calculates the ptk by using a custom PRF512 algorithm. The ptk is
   * calculated from the pmk and the two salts.
   *
   * @param pmk: the pmk
   * @param dynamic_B_salt: the dynamic salt, calculated by calc_dynamic_B_salt
   * @param ptk: pointer to a buffer to output the ptk in
   *
   */

  char buffer[4 * SHA_DIGEST_LENGTH] = {0};
  unsigned int len;

  /* we perform 4 iterations of HMAC */
  for (int i = 0; i < 4; i++) {
    char hmac_arg[256] = {0};

    /* we perform the HMAC on: const_A_salt || bytes(0) || dynamic_B_salt ||
     * bytes(i) */
    memcpy(hmac_arg, CONST_A_SALT, CONST_A_SALT_LEN);
    hmac_arg[CONST_A_SALT_LEN] = 0;
    memcpy(hmac_arg + CONST_A_SALT_LEN + 1, dynamic_B_salt, SALT_LEN);
    hmac_arg[CONST_A_SALT_LEN + SALT_LEN + 1] = i;

    /* calculate the HMAC, using sha1 */
    // HMAC(EVP_sha1(), pmk, PMK_LEN, hmac_arg, CONST_A_SALT_LEN + SALT_LEN + 2,
    //      buffer + i * SHA_DIGEST_LENGTH, &len);
    hmac_sha1((const char*)hmac_arg, CONST_A_SALT_LEN + SALT_LEN + 2, (const char*)pmk, PMK_LEN, (char*)(buffer + i * SHA_DIGEST_LENGTH));
  }

  /* copy final calculation to the ptk buffer given */
  memcpy(ptk, buffer, PTK_LEN);
}

void calc_mic_from_ptk(const char *ptk,
                       const char *second_handshake_packet,
                       char *mic, int eapol_len) {
  /**
   * calculates the mic, from the ptk and the second packet from the four-way
   * handshake.
   *
   * @param ptk: the ptk
   * @param second_handshake_packet: the raw bytes of the second packet from the
   * four way handshake
   * @param mic: pointer to a buffer to output the mic in
   *
   */
  char hmac_result[20]; // sha 1 length
  char hmac_arg[256] = {0};
  int mic_len;

  /* we perform the hmac on: second_packet[:81] || 0 * MIC_LEN ||
   * second_packet[97:] */
  memcpy(hmac_arg, second_handshake_packet, 81);
  memcpy(hmac_arg + 81, EMPTY_MIC, MIC_LEN);
  memcpy(hmac_arg + 81 + MIC_LEN, second_handshake_packet + 97, eapol_len - 97);

  hmac_sha1(hmac_arg, eapol_len, ptk, MIC_LEN, hmac_result);
  memcpy(mic, hmac_result, MIC_LEN);
}

void calc_mic_from_passphrase(const char *ssid, const char *client_mac, const char *server_mac,
                              const char *client_nonce, const char *server_nonce,
                              const int second_packet_length,
                              const char *second_handshake_packet, const char *passphrase,
                              char *mic) {
  /**
   * calculates the mic from the input variables, outputs it using the provided
   * mic pointer
   *
   * @param ssid: the ssid
   * @param client_mac: the client's mac address
   * @param server_mac: the server's mac address
   * @param client_nonce: client nonce
   * @param server_nonce: server nonce
   * @param second_packet_length: the length (in bytes) of the second handshake
   * packet
   * @param second_handshake_packet: the raw bytes of the second packet from the
   * four way handshake
   * @param passphrase: passphrase to calculate mic for
   * @param mic: pointer to a buffer to output the mic in
   *
   */

  // prepare buffers
  char pmk[PMK_LEN];
  char ptk[PTK_LEN];
  char dynamic_B_salt[SALT_LEN] = {0};

  pbkdf2_sha1(passphrase, strlen(passphrase), ssid, strlen(ssid), HMAC_SHA1_ITER, PMK_LEN, (char*)pmk);

  calc_dynamic_B_salt(client_mac, server_mac, client_nonce, server_nonce,
                      (char*)dynamic_B_salt);
  calc_ptk_by_custom_PRF512(pmk, dynamic_B_salt, ptk);

  calc_mic_from_ptk(ptk, second_handshake_packet, mic, second_packet_length);
}

void mic(const char *password, int password_length, const char *ssid,
         const char client_mac[MAC_LENGTH], const char server_mac[MAC_LENGTH],
         const char client_nonce[NONCE_LENGTH],
         const char server_nonce[NONCE_LENGTH], const char *second_packet,
         int second_packet_length, char result[MIC_LENGTH]) {
  calc_mic_from_passphrase(ssid, client_mac, server_mac, client_nonce,
                           server_nonce, second_packet_length, second_packet,
                           password, result);
}