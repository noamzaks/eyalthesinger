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
#define MAX_MIC_COMPUTATIONS 100
#define MAC_LENGTH 6
#define NONCE_LENGTH 32
#define MIC_LENGTH 16
#define SECOND_PACKET_LENGTH 121

#define PORT 5510


typedef struct {
    char ssid[32];
    char client_mac[MAC_LENGTH * 2 + 1];
    char server_mac[MAC_LENGTH * 2 + 1];
    char client_nonce[NONCE_LENGTH * 2 + 1];
    char server_nonce[NONCE_LENGTH * 2 + 1];
    char mic[MIC_LENGTH * 2 + 1];
    char password[MAX_PASSWORD_LENGTH];
    char second_packet[SECOND_PACKET_LENGTH * 2 + 1];
    int second_packet_length;
} WPA_Info_string;

typedef struct {
    char ssid[32];
    unsigned char client_mac[MAC_LENGTH];
    unsigned char server_mac[MAC_LENGTH];
    unsigned char client_nonce[NONCE_LENGTH];
    unsigned char server_nonce[NONCE_LENGTH];
    unsigned char mic[MIC_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    unsigned char second_packet[SECOND_PACKET_LENGTH];
    int second_packet_length;
} WPA_Info;


WPA_Info_string wpa_info_string;
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


// Convert char[] to string
void convert_to_string(const unsigned char * source, char * dest, int length){
for (int i = 0; i < length; i++) {
        sprintf(dest + 2 * i, "%02x", source[i]);
    }
    dest[2 * length] = '\0'; 
}

// Fill array with random values
void generate_random_array(unsigned char *array, int length){
    for (int i = 0; i < length; i++)
    {
        array[i] = rand() % 256;
    }
}


// Create the second EAPOL handshake packet
void create_second_handshake_packet() {
    // We take an existing EAPOL handshake packet and just modify the server_nonce
    unsigned char packet[SECOND_PACKET_LENGTH] = {0x01, 0x03, 0x00, 0x75, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x3f, 0x04, 0x5e, 0x6b, 0x81, 0xf5, 0x6f, 0x7c, 0xeb, 0xbb, 0xdb, 0xb9, 0xdb, 0xfb, 0x62, 0xb3, 0xdb, 0x8a, 0x39, 0x2c, 0x33, 0x99, 0x62, 0xb1, 0xb5, 0xa3, 0xad, 0xdf, 0xc2, 0xe3, 0x97, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71, 0xb1, 0x94, 0x2d, 0x7a, 0xd8, 0xf8, 0x6e, 0x6c, 0x28, 0x8a, 0xe3, 0xf6, 0x1c, 0x2e, 0xc7, 0x00, 0x16, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    // Replace the WPA Key Nonce with the server nonce
    memcpy(&packet[17], wpa_info.server_nonce, NONCE_LENGTH);

    // Copy the packet to WPA_Info structure
    memcpy(wpa_info.second_packet, packet, SECOND_PACKET_LENGTH);
    wpa_info.second_packet_length = SECOND_PACKET_LENGTH;
}


// Generate random data for nonces, SSID...
void generate_random_data() {
    // Random SSID
    snprintf(wpa_info.ssid, sizeof(wpa_info.ssid), "CTF_SSID_%d", rand() % 1000);

    // Random client and server nonces
    generate_random_array(wpa_info.client_nonce, NONCE_LENGTH);
    generate_random_array(wpa_info.server_nonce, NONCE_LENGTH);

    // Random MAC addresses
    generate_random_array(wpa_info.client_mac, MAC_LENGTH);
    generate_random_array(wpa_info.server_mac, MAC_LENGTH);
    // Create second EAPOL handshake packet
    create_second_handshake_packet();
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
    json_object_object_add(jobj, "ssid", json_object_new_string(wpa_info_string.ssid));
    json_object_object_add(jobj, "client_mac", json_object_new_string(wpa_info_string.client_mac));
    json_object_object_add(jobj, "server_mac", json_object_new_string(wpa_info_string.server_mac));
    json_object_object_add(jobj, "client_nonce", json_object_new_string(wpa_info_string.client_nonce));
    json_object_object_add(jobj, "server_nonce", json_object_new_string(wpa_info_string.server_nonce));
    json_object_object_add(jobj, "second_packet", json_object_new_string(wpa_info_string.second_packet));
    json_object_object_add(jobj, "mic", json_object_new_string((char *)wpa_info_string.mic)); 
    // Send the JSON to the client
    const char *json_str = json_object_to_json_string(jobj);

    printf("%s\n", json_str);

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

    // Random packet data (nonces, SSID)
    generate_random_data();

    // Estimate the time limit for client to respond
    estimate_time_limit();

    //calculate the mic
    mic(wpa_info.password, strlen(wpa_info.password),
        wpa_info.ssid, wpa_info.client_mac, wpa_info.server_mac,
        wpa_info.client_nonce, wpa_info.server_nonce, (char *)wpa_info.second_packet,
        wpa_info.second_packet_length, wpa_info.mic);

}


void convert_wpa_info_to_string(){
    
    convert_to_string(wpa_info.client_mac, wpa_info_string.client_mac, MAC_LENGTH);
    convert_to_string(wpa_info.server_mac, wpa_info_string.server_mac, MAC_LENGTH);
    convert_to_string(wpa_info.client_nonce, wpa_info_string.client_nonce, NONCE_LENGTH);
    convert_to_string(wpa_info.server_nonce, wpa_info_string.server_nonce, NONCE_LENGTH);
    convert_to_string(wpa_info.second_packet, wpa_info_string.second_packet, SECOND_PACKET_LENGTH);
    convert_to_string(wpa_info.mic, wpa_info_string.mic, MIC_LENGTH);

    // Other data can stay as is
    strncpy(wpa_info_string.ssid, wpa_info.ssid, 32);
    wpa_info_string.second_packet_length = wpa_info.second_packet_length;
    
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

    // generate the WPA challenge
    initiate_wpa_info();

    // Convert the values to strings
    convert_wpa_info_to_string(); 

    // Send WPA info as JSON to the client
    send_wpa_info(client_socket);

    // Receive the password from the client and verify
    receive_password_and_verify(client_socket);
    
    // Close sockets
    close(client_socket);
    close(server_socket);
    return 0;
}

