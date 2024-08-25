#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"
#include "sha256.h"
#include "utilities.h"
#include "wpa.h"

#define MAX_LINE_LENGTH 1024

#define EXIT_SUCCESS 0
#define EXIT_FINISHED 1 // finished going over wordlist but password not found
#define EXIT_INTERRUPTED 2

// Maps 0..9 and a..f to 0..15
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

static void load_hex(const char *hexdump, char *data) {
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

int current_line = 0;

void handle_sigint(int signal) {
  printf("interrupted on line %d\n", current_line);
  exit(EXIT_INTERRUPTED);
}

static inline int get_line(char *line) {
  char *current = line;
  char c = getchar();
  while (c != EOF && c != '\n') {
    *current = c;
    current++;

    if (current == line + MAX_LINE_LENGTH) {
      fprintf(stderr, "max password limit exceeded on line %d\n",
              current_line + 1);
      exit(-1);
    }

    c = getchar();
  }
  if (c == EOF) {
    exit(EXIT_FINISHED);
  }

  *current = '\0';
  return current - line;
}

int main(int argc, char *argv[]) {

#if defined(_POSIX_VERSION)
  signal(SIGINT, handle_sigint);
#endif

  char password[MAX_LINE_LENGTH];

  if (strcmp(argv[1], "sha256") == 0) {
    assert(strlen(argv[2]) == SHA256_LENGTH * 2);
    char result[SHA256_LENGTH];
    load_hex(argv[2], result);

    while (true) {
      int password_length = get_line(password);

      char hash[SHA256_LENGTH];
      sha256(password, hash);
      if (memcmp(result, hash, SHA256_LENGTH) == 0) {
        printf("%s\n", password);
        break;
      }

      current_line++;
    }
  } else if (strcmp(argv[1], "sha1") == 0) {
    assert(strlen(argv[2]) == SHA_DIGEST_LENGTH * 2);
    char result[SHA_DIGEST_LENGTH];
    load_hex(argv[2], result);

    while (true) {
      int password_length = get_line(password);

      char hash[SHA_DIGEST_LENGTH];
      sha1(password, password_length, hash);
      if (memcmp(result, hash, SHA_DIGEST_LENGTH) == 0) {
        printf("%s\n", password);
        break;
      }

      current_line++;
    }
  } else if (strcmp(argv[1], "wpa") == 0) {
    char *ssid = assert_malloc(strlen(argv[2]) / 2);
    load_hex(argv[2], ssid);
    char client_mac[MAC_LENGTH];
    assert(strlen(argv[3]) == MAC_LENGTH * 2);
    load_hex(argv[3], client_mac);
    char server_mac[MAC_LENGTH];
    assert(strlen(argv[4]) == MAC_LENGTH * 2);
    load_hex(argv[4], server_mac);
    char client_nonce[NONCE_LENGTH];
    assert(strlen(argv[5]) == NONCE_LENGTH * 2);
    load_hex(argv[5], client_nonce);
    char server_nonce[NONCE_LENGTH];
    assert(strlen(argv[6]) == NONCE_LENGTH * 2);
    load_hex(argv[6], server_nonce);
    int second_packet_length = strlen(argv[7]) / 2;
    char *second_packet = assert_malloc(second_packet_length);
    load_hex(argv[7], second_packet);
    char result[MIC_LENGTH];
    assert(strlen(argv[8]) == MIC_LENGTH * 2);
    load_hex(argv[8], result);

    while (true) {
      int password_length = get_line(password);

      char hash[MIC_LENGTH];
      mic(password, password_length, ssid, client_mac, server_mac, client_nonce,
          server_nonce, second_packet, second_packet_length, hash);

      if (memcmp(result, hash, MIC_LENGTH) == 0) {
        printf("%s\n", password);
        break;
      }

      current_line++;
    }
  }

  return EXIT_SUCCESS;
}