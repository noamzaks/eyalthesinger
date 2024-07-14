#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"
#include "sha256.h"

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
  signal(SIGINT, handle_sigint);

  if (argc != 3) {
    fprintf(stderr, "usage: %s cipher hash\n", argv[0]);
    exit(-1);
  }

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
    assert(strlen(argv[2]) == SHA1_LENGTH * 2);
    char result[SHA1_LENGTH];
    load_hex(argv[2], result);

    while (true) {
      int password_length = get_line(password);

      char hash[SHA1_LENGTH];
      sha1(password, password_length, hash);
      if (memcmp(result, hash, SHA1_LENGTH) == 0) {
        printf("%s\n", password);
        break;
      }

      current_line++;
    }
  }

  return EXIT_SUCCESS;
}