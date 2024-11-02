#include "utilities.h"

#include <assert.h>
#include <stdlib.h>

void *assert_malloc(int size) {
  void *result = malloc(size);

  assert(result != NULL);

  return result;
}