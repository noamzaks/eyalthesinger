#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

#define MAX_PASSWORD_SIZE 1024

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

static void load_hexdump(const char *hexdump, char *data) {
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

int main(int argc, char *argv[]) {
  signal(SIGINT, handle_sigint);

  if (argc != 3) {
    fprintf(stderr, "usage: %s cipher hash\n", argv[0]);
    exit(-1);
  }

  char password[MAX_PASSWORD_SIZE];

  if (strcmp(argv[1], "sha256") == 0) {
    assert(strlen(argv[2]) == 64);
    char result[32];
    load_hexdump(argv[2], result);

    while (true) {
      char *current = password;
      char c;
      while ((c = getchar()) != EOF && c != '\n') {
        *current = c;
        current++;

        if (current == password + MAX_PASSWORD_SIZE) {
          fprintf(stderr, "max password limit exceeded on line %d\n",
                  current_line + 1);
          exit(-1);
        }
      }
      if (c == EOF) {
        exit(EXIT_FINISHED);
      }
      *current = '\0';

      if (sha256_check(password, result)) {
        printf("%s\n", password);
        break;
      }

      current_line++;
    }
  }

  return EXIT_SUCCESS;
}