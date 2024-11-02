#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wpa.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "sha1.h"

// These are the fields you need to extract from the packet. We KNOW that the passphrase is LetsCalculateTheMIC!
#define PASS_PHRASE "LetsCalculateTheMIC"
#define SSID ""
#define AP_MAC ""
#define CLIENT_MAC ""
#define CLIENT_NONCE ""
#define SERVER_NONCE ""
#define EMPTY_MIC ""
#define SECOND_HANDSHAKE_EAPOL ""

/* NOTE: you have length constanats available in wpa.h (under utilities)*/

/* constant salt used in the algorithm ('A') */
#define CONST_A_SALT ""
#define CONST_A_SALT_LEN -1


void calc_dynamic_B_salt(const char *client_mac, const char *server_mac,
                         const char *client_nonce, const char *server_nonce,
                         char *dynamic_B_salt) {
  /**
   * calculates the dynamic salt used in the algorithm ('B')
   *
   * @param client_mac: the client's mac address
   * @param server_mac: the server's mac address
   * @param client_nonce: client nonce
   * @param server_nonce: server nonce
   * @param dynamic_B_salt: pointer to a buffer to output the B salt in
   *
   */
}

void calc_kck_by_custom_PRF512(const char *pmk, const char *dynamic_B_salt,
                               char *kck) {
  /**
   * calculates the KCK by using a custom PRF512 algorithm. The kck is
   * calculated from the pmk and the two salts.
   *
   * @param pmk: the pmk
   * @param dynamic_B_salt: the dynamic salt, calculated by calc_dynamic_B_salt
   * @param kck: pointer to a buffer to output the kck in
   *
   */
}

void calc_mic_from_kck(const char *kck, const char *second_handshake_eapol,
                       char *mic, int eapol_len) {
  /**
   * calculates the mic, from KCK and the second packet eapol layer from the four-way
   * handshake.
   *
   * @param kck: the KCK
   * @param second_handshake_eapol: the raw bytes of the eapol layer of the second packet from the
   * four way handshake
   * @param mic: pointer to a buffer to output the mic in
   * @param eapol_len: length of the second handshake packet
   *
   */
}

void calc_mic_from_passphrase(const char *ssid, const char *client_mac,
                              const char *server_mac, const char *client_nonce,
                              const char *server_nonce,
                              const int second_packet_length,
                              const char *second_handshake_eapol,
                              const char *passphrase, char *mic) {
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
   * @param second_handshake_eapol: the raw bytes of the eapol layer of the second packet from the
   * four way handshake
   * @param passphrase: passphrase to calculate mic for
   * @param mic: pointer to a buffer to output the mic in
   *
   */

  // prepare buffers
  char pmk[PMK_LENGTH];
  char kck[KCK_LENGTH];
  char dynamic_B_salt[SALT_LENGTH] = {0};

  // first, calculate the pmk
  pbkdf2_sha1(passphrase, strlen(passphrase), ssid, strlen(ssid),
              HMAC_SHA1_ITER, PMK_LENGTH, (char *)pmk);

  // Then, calculate the dynamic salt, B
  calc_dynamic_B_salt(client_mac, server_mac, client_nonce, server_nonce,
                      (char *)dynamic_B_salt);
  
  // Derive KCK from the pmk and salt
  calc_kck_by_custom_PRF512(pmk, dynamic_B_salt, kck);

  // Derive the mic from the KCK and raw, second handshake packet
  calc_mic_from_kck(kck, second_handshake_eapol, mic, second_packet_length);
}