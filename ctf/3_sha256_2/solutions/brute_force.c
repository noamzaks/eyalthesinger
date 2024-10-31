#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>

#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$&*"
#define CHARSET_SIZE (sizeof(CHARSET) - 1)
#define MAX_PASS_LEN 64
#define NUM_THREADS 8

typedef struct {
    int thread_id;
    const char *target_hash;
    int start_index;
    int step_size;
    int *found;
} ThreadData;

char target_hash[SHA256_LENGTH] = {0xc1, 0x2d, 0xa9, 0x03, 0xca, 0x98, 0xbe, 0x3a, 0x94, 0x3b, 0x78, 0x40, 0x6d, 0x48, 0xcf, 0x61, 0xf4, 0xfd, 0x39, 0x5a, 0xfd, 0x36, 0x6f, 0xfe, 0x04, 0xea, 0xa6, 0xf9, 0x05, 0xfb, 0x84, 0x99};

int compare_hash(const char *target_hash, char *hash_to_check) {
    for (int i = 0; i < SHA256_LENGTH; i++) {
        if (target_hash[i] != hash_to_check[i]) {
            return 0;
        }
    }
    return 1;
}

void *brute_force_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    char buffer[MAX_PASS_LEN + 1];
    char hash_calc[SHA256_LENGTH];
    int counter = 0;
    for (int length = 1; length <= MAX_PASS_LEN && !(*data->found); length++) {
        unsigned long combinations = pow(CHARSET_SIZE, length);
        for (unsigned long i = data->start_index; i < combinations && !(*data->found); i += data->step_size) {
            int j;
            // Build the string for the current combination
            for (j = 0; j < length; j++) {
                buffer[j] = CHARSET[(i / (unsigned long)pow(CHARSET_SIZE, j)) % CHARSET_SIZE];
            }
            buffer[length] = '\0';


            sha256(buffer, hash_calc);
            if (compare_hash(data->target_hash, hash_calc)) {
                printf("Thread %d found password: %s\n", data->thread_id, buffer);
                *data->found = 1;
                return NULL;
            }

            
        }
    }
    return NULL;
}

void brute_force(const char *target_hash) {
    pthread_t threads[NUM_THREADS];
    ThreadData thread_data[NUM_THREADS];
    int found = 0;

    // Initialize thread data and create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].target_hash = target_hash;
        thread_data[i].start_index = i;
        thread_data[i].step_size = NUM_THREADS;
        thread_data[i].found = &found;

        if (pthread_create(&threads[i], NULL, brute_force_thread, &thread_data[i]) != 0) {
            perror("Error creating thread");
            return;
        }
    }

    // Wait for threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    if (!found) {
        printf("Password not found.\n");
    }
}

double get_time_in_seconds() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}


int main() {

    double start_time = get_time_in_seconds();

    brute_force(target_hash);
    
    double end_time = get_time_in_seconds();
    
    printf("This took %f seconds\n", end_time - start_time);

    return 0;
}