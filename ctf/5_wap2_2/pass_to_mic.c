#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

// These are the fields you need to extract from the packet. We KNOW that the passphrase is 123456789!
#define PASS_PHRASE "123456789"
#define SSID ""
#define AP_MAC ""
#define CLIENT_MAC ""
#define client_nonce ""
#define server_nonce ""
#define DATA ""
#define EMPTY_MIC ""

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


void calc_dynamic_B_salt(char* client_mac, char* server_mac, char* client_nonce, char* server_nonce, char* dynamic_B_salt){
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


void calc_ptk_by_custom_PRF512(const unsigned char *pmk, const unsigned char *dynamic_B_salt, unsigned char *ptk) {
    /** 
    * calculates the ptk from the pmk and the two salts. 
    * 
    * @param pmk: the pmk
    * @param dynamic_B_salt: the dynamic salt, calculated by calc_dynamic_B_salt
    * @param ptk: pointer to a buffer to output the ptk in
    *
    */ 
}



void calc_mic_from_ptk(const unsigned char *ptk, const unsigned char *second_handshake_packet, unsigned char *mic) {
    /** 
    * calculates the mic, from the ptk and the second packet from the four-way handshake. 
    * 
    * @param ptk: the ptk
    * @param second_handshake_packet: the raw bytes of the second packet from the four way handshake
    * @param mic: pointer to a buffer to output the mic in
    *
    */ 
}


void calc_mic_from_passphrase(char *ssid, char *client_mac, char *server_mac, char *client_nonce, char *server_nonce, int second_packet_length, char *second_handshake_packet, char *passphrase, char *mic) {
    /** 
    * calculates the mic from the input variables, outputs it using the provided mic pointer
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
    unsigned char pmk[PMK_LEN];
    unsigned char ptk[PTK_LEN];
    unsigned char dynamic_B_salt[SALT_LEN] = {0};

    // first, calculate the pmk
    PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), (unsigned char *)ssid, strlen(ssid), HMAC_SHA1_ITER, PMK_LEN, pmk);

    // First, Calculate the dynamic salt, B
    calc_dynamic_B_salt(client_mac, server_mac, client_nonce, server_nonce, dynamic_B_salt);
    // Derive PTK from the pmk and salt
    calc_ptk_by_customPRF512(pmk, dynamic_B_salt, ptk);

    // Derive the mic from the ptk and raw, second handshake packet
    calc_mic_from_ptk(ptk, second_handshake_packet, mic);
}
