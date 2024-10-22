#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "wpa.h"  


#define PASSWORD_FILE "rockyou.txt"
#define MAX_PASSWORD_LENGTH 140
#define MAX_MIC_COMPUTATIONS 1000
#define MAC_LENGTH 6
#define NONCE_LENGTH 32
#define MIC_LENGTH 16
#define SECOND_PACKET_LENGTH 121

#define PORT 5510


typedef struct {
    char ssid[32];
    char client_mac[MAC_LENGTH * 2 + 1];
    char server_mac[MAC_LENGTH * 2 + 1];
    unsigned char client_nonce[NONCE_LENGTH * 2 + 1];
    unsigned char server_nonce[NONCE_LENGTH * 2 + 1];
    unsigned char mic[MIC_LENGTH * 2 + 1];
    char password[MAX_PASSWORD_LENGTH];
    unsigned char second_packet[SECOND_PACKET_LENGTH * 2 + 1];
    int second_packet_length;
} WPA_Info;

WPA_Info wpa_info;
unsigned int time_limit_seconds;
unsigned char encrypted_flag[AES_BLOCK_SIZE] = {0xf5, 0x27, 0xad, 0x1f, 0x5a, 0x1f, 0x26, 0xe3, 0xdb, 0xea, 0xb5, 0xb3, 0x6f, 0x7d, 0x0f, 0x5d};
unsigned char key[16] = {0xdd, 0x05, 0x24, 0x81, 0xb9, 0x96, 0xa7, 0xd8, 0x89, 0xd8, 0x8b, 0xcb, 0xe7, 0x9a, 0x69, 0x78};  



//decrypt the flag
void decrypt(const unsigned char *key, const unsigned char *ciphertext, unsigned char *plaintext) {
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 128, &dec_key);
    AES_decrypt(ciphertext, plaintext, &dec_key);
}

// Send the flag to the client
void send_flag(int client_socket) {
    char decrypted_flag[256];
    
    // Decrypt the flag using the correct password
    decrypt(key, encrypted_flag, decrypted_flag);
    
    // Send the decrypted flag to the client
    send(client_socket, decrypted_flag, strlen(decrypted_flag), 0);
}

// Send a failure message to the client
void send_failure(int client_socket) {
    const char *failure_message = "Failure: Incorrect password or timeout.\n";
    send(client_socket, failure_message, strlen(failure_message), 0);
}

// Generate a random MAC address
void generate_mac(char *mac_str) {
    for (int i = 0; i < 6; i++) {
        sprintf(mac_str + 2 * i, "%02x", rand() % 256);
    }
    mac_str[17] = '\0'; 
}

// Generate random data for nonces, SSID...
void generate_random_data() {
    // Random SSID
    snprintf(wpa_info.ssid, sizeof(wpa_info.ssid), "CTF_SSID_%d", rand() % 1000);

    // Random client and server nonces
    for (int i = 0; i < NONCE_LENGTH; i++) {
        sprintf(wpa_info.client_nonce + 2 * i, "%02x", rand() % 256);
        sprintf(wpa_info.server_nonce + 2 * i, "%02x", rand() % 256);
    }
}

// Create the second EAPOL handshake packet
void create_second_handshake_packet() {
    // We take an existing EAPOL handshake packet and just modify the server_nonce
    unsigned char packet[SECOND_PACKET_LENGTH*2 + 1] = "0103007502010a000000000000000000013f045e6b81f56f7cebbbdbb9dbfb62b3db8a392c339962b1b5a3addfc2e397b0000000000000000000000000000000000000000000000000000000000000000071b1942d7ad8f86e6c288ae3f61c2ec70016000102030405060708090a0b0c0d0e0f101112131415";
    // Replace the WPA Key Nonce with the server nonce
    memcpy(&packet[34], wpa_info.server_nonce, NONCE_LENGTH*2);

    // Copy the packet to WPA_Info structure
    memcpy(wpa_info.second_packet, packet, SECOND_PACKET_LENGTH*2);
    wpa_info.second_packet_length = SECOND_PACKET_LENGTH;
}

// Estimate the time limit for client to respond
void estimate_time_limit() {
    clock_t start = clock();

    char result[MIC_LENGTH + 1];
    char password[MAX_PASSWORD_LENGTH];
    // 1000 MIC computations
    for (int i = 0; i < MAX_MIC_COMPUTATIONS; i++) {
        sprintf(password, "%d", i); 
        mic(password, strlen(password),
        wpa_info.ssid, wpa_info.client_mac, wpa_info.server_mac,
        wpa_info.client_nonce, wpa_info.server_nonce, (char *)wpa_info.second_packet,
        wpa_info.second_packet_length, result);

    }
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    // Estimate the total time for 14,000,000 MIC computations
    double estimated_total_time = (elapsed / MAX_MIC_COMPUTATIONS) * 14000000;

    // Divide by 16 to get the time limit
    time_limit_seconds = (unsigned int)(estimated_total_time / 16);
    printf("Time limit set to: %u seconds\n", time_limit_seconds);
}

// Function to select a random password from rockyou.txt
void select_random_password() {
    FILE *file = fopen(PASSWORD_FILE, "r");
    if (!file) {
        perror("Error opening password file");
        exit(1);
    }

    // Count the number of lines (passwords)
    int line_count = 0;
    char line[MAX_PASSWORD_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        line_count++;
    }

    // Select a random line
    srand(time(NULL));
    int random_line = rand() % line_count;

    // Read the random password
    rewind(file);
    for (int i = 0; i <= random_line; i++) {
        fgets(line, sizeof(line), file);
    }
    fclose(file);

    // Remove the newline character at the end of the password
    line[strcspn(line, "\r\n")] = '\0';
    strncpy(wpa_info.password, line, MAX_PASSWORD_LENGTH - 1);
    // printf("Selected password: %s\n", wpa_info.password);
}

// Generate WPA info and send it as JSON to the client
void send_wpa_info(int client_socket) {
    
    // Create JSON object with the WPA data
    struct json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "ssid", json_object_new_string(wpa_info.ssid));
    json_object_object_add(jobj, "client_mac", json_object_new_string(wpa_info.client_mac));
    json_object_object_add(jobj, "server_mac", json_object_new_string(wpa_info.server_mac));
    json_object_object_add(jobj, "client_nonce", json_object_new_string(wpa_info.client_nonce));
    json_object_object_add(jobj, "server_nonce", json_object_new_string(wpa_info.server_nonce));
    json_object_object_add(jobj, "second_packet", json_object_new_string_len((char *)wpa_info.second_packet, SECOND_PACKET_LENGTH*2 + 1));
    json_object_object_add(jobj, "mic", json_object_new_string((char *)wpa_info.mic)); // Assuming mic can be cast to string

    // Send the JSON to the client
    const char *json_str = json_object_to_json_string(jobj);

    send(client_socket, json_str, strlen(json_str), 0);

    // Free JSON object
    json_object_put(jobj);
}



// Function to receive password and verify
void receive_password_and_verify(int client_socket) {
    // Set up a timeout for receiving data from the client
    struct timeval tv;
    tv.tv_sec = time_limit_seconds;
    tv.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    char received_password[MAX_PASSWORD_LENGTH];
    int bytes_received = recv(client_socket, received_password, sizeof(received_password), 0);
    
    if (bytes_received <= 0) {
        printf("Client failed to respond in time or an error occurred.\n");
        send_failure(client_socket);
        return;
    }

    // Remove any trailing newline characters
    received_password[strcspn(received_password, "\r\n")] = '\0';

    // Compare the passwords
    if (strncmp(wpa_info.password, received_password, strlen(wpa_info.password)) == 0) {
        // Password is correct, send the flag
        send_flag(client_socket);
    } else {
        // Incorrect password
        printf("Incorrect password provided by client.\n");
        send_failure(client_socket);
    }
}

void initiate_wpa_info(){
    // select_random_password
    select_random_password();

    // Random MAC addresses
    generate_mac(wpa_info.client_mac);
    generate_mac(wpa_info.server_mac);

    // Random data (nonces, SSID)
    generate_random_data();

    // Create second EAPOL handshake packet
    create_second_handshake_packet();


    // Estimate the time limit for client to respond
    estimate_time_limit();

    unsigned char calculated_mic[MIC_LENGTH];

    mic(wpa_info.password, strlen(wpa_info.password),
        wpa_info.ssid, wpa_info.client_mac, wpa_info.server_mac,
        wpa_info.client_nonce, wpa_info.server_nonce, (char *)wpa_info.second_packet,
        wpa_info.second_packet_length, calculated_mic);


    for (int i = 0; i < MIC_LENGTH; i++) {
        sprintf(wpa_info.mic + 2 * i, "%02x", calculated_mic[i]);
    }

}


int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Prepare the sockaddr_in structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_socket, 1) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Waiting for client connection...\n");
    
    // Accept client connection
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_socket < 0) {
        perror("Accept failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Client connected!\n");

    initiate_wpa_info();

    // Generate WPA info and send it as JSON to the client
    send_wpa_info(client_socket);

    // Receive the password from the client and verify
    receive_password_and_verify(client_socket);
    
    // Close sockets
    close(client_socket);
    close(server_socket);
    return 0;
}

