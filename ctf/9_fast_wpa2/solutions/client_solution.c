/*
Need to compile with the -ljson-c flag
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h> 
#include <stdbool.h>

#include "wpa.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5510

#define BUFFER_SIZE 1024
#define PASSWORD_FILE "rockyou.txt"
#define MAX_PASSWORD_LENGTH 140
#define MAX_MIC_COMPUTATIONS 1000
#define MAC_LENGTH 6
#define NONCE_LENGTH 32
#define MIC_LENGTH 16
#define SECOND_PACKET_LENGTH 121
#define NUM_THREADS 8


typedef struct {
    unsigned char ssid[32];
    unsigned char client_mac[MAC_LENGTH];
    unsigned char server_mac[MAC_LENGTH];
    unsigned char client_nonce[NONCE_LENGTH];
    unsigned char server_nonce[NONCE_LENGTH];
    unsigned char mic[MIC_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    unsigned char second_packet[SECOND_PACKET_LENGTH];
    int second_packet_length;
    long start_offset;
    long end_offset;
    const char *password_file_path;
    atomic_bool *password_found;
    int server_socket;
} WPA_Info;


// Function to connect to the server
int connect_to_server(const char *server_ip, int server_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server at %s:%d\n", server_ip, server_port);
    return sock;
}

// Function to receive JSON data from the server
void receive_json_data(int socket, char *json_buffer, size_t buffer_size) {
    int bytes_received = recv(socket, json_buffer, buffer_size - 1, 0);
    if (bytes_received <= 0) {
        perror("Error receiving data from server");
        close(socket);
        exit(EXIT_FAILURE);
    }
    json_buffer[bytes_received] = '\0';  // Null-terminate the string
}

// Function to parse the received JSON data
void parse_json_data(const char *json_str, char *ssid, char *client_mac, char *server_mac,
                     char *client_nonce, char *server_nonce, unsigned char *second_packet, int *second_packet_length, char *target_mic, int server_socket) {
    struct json_object *parsed_json = json_tokener_parse(json_str);
    if (parsed_json == NULL) {
        fprintf(stderr, "Error parsing JSON data.\n");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    struct json_object *j_ssid, *j_client_mac, *j_server_mac, *j_client_nonce, *j_server_nonce, *j_second_packet, *j_mic, *j_target_mic;
    
    json_object_object_get_ex(parsed_json, "ssid", &j_ssid);
    json_object_object_get_ex(parsed_json, "client_mac", &j_client_mac);
    json_object_object_get_ex(parsed_json, "server_mac", &j_server_mac);
    json_object_object_get_ex(parsed_json, "client_nonce", &j_client_nonce);
    json_object_object_get_ex(parsed_json, "server_nonce", &j_server_nonce);
    json_object_object_get_ex(parsed_json, "second_packet", &j_second_packet);
    json_object_object_get_ex(parsed_json, "mic", &j_target_mic);

    strcpy(ssid, json_object_get_string(j_ssid));
    strcpy(client_mac, json_object_get_string(j_client_mac));
    strcpy(server_mac, json_object_get_string(j_server_mac));
    strcpy(client_nonce, json_object_get_string(j_client_nonce));
    strcpy(server_nonce, json_object_get_string(j_server_nonce));
    strcpy(target_mic, json_object_get_string(j_target_mic));

    const char *second_packet_str = json_object_get_string(j_second_packet);
    *second_packet_length = strlen(second_packet_str) / 2;
    memcpy(second_packet, second_packet_str, (*second_packet_length)*2);

    json_object_put(parsed_json);  // Free memory
}

// Function to send the guessed password to the server
void send_password(int socket, const char *password) {
    send(socket, password, strlen(password), 0);
}

// Maps 0..9 and a..f to 0..15
// for load_hex function
static char hex_values[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 1, 2, 3, 4, 5,  6,  7,  8,  9,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,
};
// Convert string hex to unsigned char
void load_hex(const char *hexdump, char *data) {
  while (*hexdump != '\0') {
    assert(('0' <= *hexdump && *hexdump <= '9') ||
           ('a' <= *hexdump && *hexdump <= 'f'));
    assert(('0' <= *(hexdump + 1) && *(hexdump + 1) <= '9') ||
           ('a' <= *(hexdump + 1) && *(hexdump + 1) <= 'f'));

    *data = hex_values[*hexdump] * 16 + hex_values[*(hexdump + 1)];

    data++;
    hexdump += 2;
  }
}

void *dictionary_attack(void *arg) {
    WPA_Info *data = (WPA_Info *)arg;
    char password[MAX_PASSWORD_LENGTH];
    char computed_mic[MIC_LENGTH];

    printf("thread starting at %ld\n", data->start_offset);


    // Each thread opens its own file descriptor
    FILE *password_file = fopen(data->password_file_path, "r");
    if (password_file == NULL) {
        fprintf(stderr, "Error: Could not open password file in thread.\n");
        return NULL;
    }

    // Move the file pointer to the start offset
    fseek(password_file, data->start_offset, SEEK_SET);

    int counter = 0;

    // Read each password in this thread's segment of the file
    while (ftell(password_file) < data->end_offset && fscanf(password_file, "%s", password) == 1) {
        
        password[strcspn(password, "\r\n")] = '\0';
        // Calculate the MIC for the current password
        mic(password, strlen(password), data->ssid, data->client_mac, data->server_mac, data->client_nonce, 
        data->server_nonce, data->second_packet, data->second_packet_length, computed_mic);

        // Compare the calculated MIC with the target MIC
        if (memcmp(computed_mic, data->mic, 16) == 0) {
            atomic_store(data->password_found, true);
            printf("Password found: %s\n", password);
            fclose(password_file);

            send_password(data->server_socket, password);
            return NULL;
        }

        // Stop if another thread found the password
        if (atomic_load(data->password_found)) {
            fclose(password_file);
            return NULL;
        }

        counter++;
        if (data->start_offset == 0 && counter % 1000 == 0){
            printf("thread 0 completed %d\n", counter);
        }
    }

    fclose(password_file);
    return NULL;
}

// Function to get the file size
long get_file_size(FILE *file) {
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}



char* multithread_dictionary_attack(const unsigned char *ssid,
         const unsigned char client_mac[MAC_LENGTH], const unsigned char server_mac[MAC_LENGTH],
         const unsigned char client_nonce[NONCE_LENGTH],
         const unsigned char server_nonce[NONCE_LENGTH], const unsigned char *second_packet,
         int second_packet_length, char unsigned target_mic[MIC_LENGTH], char result[MAX_PASSWORD_LENGTH], int server_socket){
    
    // Load WPA information
    WPA_Info thread_data[NUM_THREADS] = {0};
    atomic_bool password_found = false;


    FILE *password_file = fopen(PASSWORD_FILE, "r");
    if (password_file == NULL) {
        printf("Error: Could not open password file.\n");
        return NULL;
    }

    long file_size = get_file_size(password_file);
    long segment_size = file_size / NUM_THREADS;
    fclose(password_file);

// Setup shared information in each thread's data
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].password_file_path = PASSWORD_FILE;
        strcpy(thread_data[i].ssid, ssid);
        memcpy(thread_data[i].client_mac, client_mac, MAC_LENGTH);
        memcpy(thread_data[i].server_mac, server_mac, MAC_LENGTH);
        memcpy(thread_data[i].client_nonce, client_nonce, NONCE_LENGTH);
        memcpy(thread_data[i].server_nonce, server_nonce, NONCE_LENGTH);
        memcpy(thread_data[i].second_packet, second_packet, second_packet_length);
        thread_data[i].second_packet_length = second_packet_length;
        memcpy(thread_data[i].mic, target_mic, MIC_LENGTH);  

        // Assign each thread a segment of the file
        thread_data[i].start_offset = i * segment_size;
        thread_data[i].end_offset = (i == NUM_THREADS - 1) ? file_size : (i + 1) * segment_size;
        thread_data[i].password_found = &password_found;
        thread_data[i].server_socket = server_socket;
    }

    // Create threads for dictionary attack
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, dictionary_attack, &thread_data[i]);
    }

    // Wait for all threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // If password not found, inform the user
    if (!atomic_load(&password_found)) {
        printf("Password not found.\n");
        return 0;
    }



}



// Main function for the client
int main() {
    char ssid[32];
    // These are the string version of the parameters, that are recieved from the json file
    char s_client_mac[MAC_LENGTH * 2 + 1] = {0}, s_server_mac[MAC_LENGTH * 2 + 1] = {0};
    char s_client_nonce[NONCE_LENGTH * 2 + 1] = {0}, s_server_nonce[NONCE_LENGTH * 2 + 1] = {0};
    char s_second_packet[SECOND_PACKET_LENGTH * 2 + 1] = {0}, s_target_mic[MIC_LENGTH * 2 + 1] = {0};
    
    //These are the ones converted to unsigned chars representing hex digits
    unsigned char client_mac[MAC_LENGTH], server_mac[MAC_LENGTH];
    unsigned char client_nonce[NONCE_LENGTH], server_nonce[NONCE_LENGTH];
    unsigned char second_packet[SECOND_PACKET_LENGTH], target_mic[MIC_LENGTH];
    
    int second_packet_length;

    // Connect to the server
    int server_socket = connect_to_server(SERVER_IP, SERVER_PORT);

    // Receive JSON data from the server
    char json_buffer[BUFFER_SIZE];
    receive_json_data(server_socket, json_buffer, sizeof(json_buffer));

    // Parse the JSON data
    parse_json_data(json_buffer, ssid, s_client_mac, s_server_mac, s_client_nonce, s_server_nonce, s_second_packet, &second_packet_length, s_target_mic, server_socket);

    // Debug information (you can remove this for the CTF)
    printf("Received WPA Info:\n");
    printf("SSID: %s\n", ssid);
    printf("Client MAC: %s\n", s_client_mac);
    printf("Server MAC: %s\n", s_server_mac);
    printf("Client Nonce: %s\n", s_client_nonce);
    printf("Server Nonce: %s\n", s_server_nonce);
    printf("Second Packet Length: %d\n", second_packet_length);
    printf("MIC: %s\n", s_target_mic);

    load_hex(s_client_nonce, client_nonce);
    load_hex(s_client_mac, client_mac);
    load_hex(s_server_mac, server_mac);
    load_hex(s_server_nonce, server_nonce);
    load_hex(s_second_packet, second_packet);
    load_hex(s_target_mic, target_mic);


    // Perform a dictionary attack, and find the password!!!!!
    char password[MAX_PASSWORD_LENGTH] = {0}; 
    multithread_dictionary_attack(ssid, client_mac, server_mac, 
    client_nonce, server_nonce, second_packet, second_packet_length, target_mic, password, server_socket);  

    // Send the found password back to the server, this is done in the thread
    // send_password(server_socket, password);

    // Receive the response (either the flag or a failure message)
    char response[BUFFER_SIZE];
    int response_length = recv(server_socket, response, sizeof(response) - 1, 0);
    if (response_length > 0) {
        response[response_length] = '\0';  // Null-terminate the response
        printf("Server Response: %s\n", response);
    } else {
        printf("No response received from server.\n");
    }

    // Close the socket connection
    close(server_socket);

    return 0;
}
