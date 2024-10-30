#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wpa.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "sha1.h"

// These are the fields you need to extract from the packet. We KNOW that the passphrase is 123456789!
#define PASS_PHRASE "LetsCalculateTheMIC"
#define SSID ""
#define AP_MAC ""
#define CLIENT_MAC ""
#define CLIENT_NONCE ""
#define SERVER_NONCE ""
#define EMPTY_MIC ""
#define SECOND_HANDSHAKE_PACKET ""

// length constants
#define EAPOL_LEN 121
#define MAC_LEN 6
#define NONCE_LEN 32
#define SALT_LEN 2 * MAC_LEN + 2 * NONCE_LEN
#define PMK_LEN 32
#define PTK_LEN 64
#define MIC_LEN 16 
#define HMAC_SHA1_ITER 4096

/* constant salt used in the algorithm ('A') */
#define CONST_A_SALT ""
#define CONST_A_SALT_LEN -1



void calc_dynamic_B_salt(const char* client_mac, const char* server_mac, const char* client_nonce, const char* server_nonce, char* dynamic_B_salt){
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


void calc_ptk_by_custom_PRF512(const char *pmk, const char *dynamic_B_salt, char *ptk) {
    /** 
    * calculates the ptk from the pmk and the two salts. 
    * 
    * @param pmk: the pmk
    * @param dynamic_B_salt: the dynamic salt, calculated by calc_dynamic_B_salt
    * @param ptk: pointer to a buffer to output the ptk in
    *
    */ 
}


void calc_mic_from_ptk(const char *ptk, const char *second_handshake_packet, char *mic, int eapol_len) {
    /** 
    * calculates the mic, from the ptk and the second packet from the four-way handshake. 
    * 
    * @param ptk: the ptk
    * @param second_handshake_packet: the raw bytes of the second packet from the four way handshake
    * @param mic: pointer to a buffer to output the mic in
    * @param eapol_len: length of the second handshake packet
    *
    */ 
}



void calc_mic_from_ptk(const char *ptk, const char *second_handshake_packet,
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

void calc_mic_from_passphrase(const char *ssid, const char *client_mac,
                              const char *server_mac, const char *client_nonce,
                              const char *server_nonce,
                              const int second_packet_length,
                              const char *second_handshake_packet,
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
    * @param second_packet_length: the length (in bytes) of the second handshake packet
    * @param second_handshake_packet: the raw bytes of the second packet from the four way handshake
    * @param passphrase: passphrase to calculate mic for
    * @param mic: pointer to a buffer to output the mic in
    *
    */

    // prepare buffers
    char pmk[PMK_LEN];
    char ptk[PTK_LEN];
    char dynamic_B_salt[SALT_LEN] = {0};

    // first, calculate the pmk
    pbkdf2_sha1(passphrase, strlen(passphrase), ssid, strlen(ssid),
                HMAC_SHA1_ITER, PMK_LEN, (char *)pmk);

    // Then, calculate the dynamic salt, B
    calc_dynamic_B_salt(client_mac, server_mac, client_nonce, server_nonce,
                        (char *)dynamic_B_salt);

    // Derive PTK from the pmk and salt
    calc_ptk_by_custom_PRF512(pmk, dynamic_B_salt, ptk);

    // Derive the mic from the ptk and raw, second handshake packet
    calc_mic_from_ptk(ptk, second_handshake_packet, mic, second_packet_length);

    printf("The mic is: %s\n", mic);
}


int main() {
    char *mic = malloc(MIC_LEN);
    if (!mic) {
        perror("Error in malloc\n");
        return -1;
    }
    calc_mic_from_passphrase(SSID, CLIENT_MAC, AP_MAC, CLIENT_NONCE, SERVER_NONCE, SECOND_HANDSHAKE_PACKET, EAPOL_LEN, PASS_PHRASE, mic);
    free(mic);
}