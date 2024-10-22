/*
 * sha256.cu Implementation of SHA256 Hashing
 *
 * Date: 12 June 2019
 * Revision: 1
 * *
 * Based on the public domain Reference Implementation in C, by
 * Brad Conte, original code here:
 *
 * https://github.com/B-Con/crypto-algorithms
 *
 * This file is released into the Public Domain.
 */

/*************************** HEADER FILES ***************************/
#include <cassert>
#include <cuda_runtime_api.h>
#include <memory.h>
#include <stdlib.h>

extern "C" {
#include "sha256.cuh"
}
/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32 // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/

typedef struct {
  BYTE data[64];
  WORD datalen;
  unsigned long long bitlen;
  WORD state[8];
} CUDA_SHA256_CTX;

/****************************** MACROS ******************************/
#ifndef ROTLEFT
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#endif

#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
__constant__ WORD k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*********************** FUNCTION DEFINITIONS ***********************/
__device__ __forceinline__ void cuda_sha256_transform(CUDA_SHA256_CTX *ctx,
                                                      const BYTE data[]) {
  WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

  for (i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) |
           (data[j + 3]);
  for (; i < 64; ++i)
    m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
    t2 = EP0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

__device__ void cuda_sha256_init(CUDA_SHA256_CTX *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

__device__ void cuda_sha256_update(CUDA_SHA256_CTX *ctx, const BYTE data[],
                                   size_t len) {
  WORD i;

  for (i = 0; i < len; ++i) {
    if (data[i] == 0) {
      break;
    }

    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      cuda_sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

__device__ void cuda_sha256_final(CUDA_SHA256_CTX *ctx, BYTE out[],
                                  BYTE *indata, WORD inlen, BYTE *target_hash) {
  WORD i;

  i = ctx->datalen;

  // Pad whatever data is left in the buffer.
  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56)
      ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64)
      ctx->data[i++] = 0x00;
    cuda_sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }

  // Append to the padding the total message's length in bits and transform.
  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  cuda_sha256_transform(ctx, ctx->data);

  // Since this implementation uses little endian byte ordering and SHA uses big
  // endian, reverse all the bytes when copying the final state to the output
  // hash.
  BYTE hash[32];
  for (i = 0; i < 4; ++i) {
    hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
    hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
  }

  // compare hash to wanted hash

  bool is_equal = true;
  for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
    if (target_hash[i] != hash[i]) {
      is_equal = false;
      break;
    }
  }

  // if success, copy indata to out
  if (is_equal) {
    for (int i = 0; i < inlen; i++) {
      out[i] = indata[i];
    }
    // cudaMemcpy(out, indata, inlen, cudaMemcpyDeviceToDevice);
  }
}

__global__ void kernel_sha256_hash(BYTE *indata, WORD inlen, BYTE *outdata,
                                   WORD n_batch, char *result) {
  WORD thread = blockIdx.x * blockDim.x + threadIdx.x;
  if (thread >= n_batch) {
    return;
  }
  BYTE *in = indata + thread * inlen;
  BYTE *out = outdata;
  CUDA_SHA256_CTX ctx;
  cuda_sha256_init(&ctx);
  cuda_sha256_update(&ctx, in, inlen);
  cuda_sha256_final(&ctx, out, indata, inlen, (unsigned char *)result);
}

extern "C" {
void mcm_cuda_sha256_hash_batch(BYTE *in, WORD inlen, BYTE *out, WORD n_batch,
                                char result[SHA256_BLOCK_SIZE]) {
  BYTE *cuda_indata;
  BYTE *cuda_outdata;
  char *cuda_result;
  cudaMalloc(&cuda_indata, inlen * n_batch);
  cudaMalloc(&cuda_outdata, SHA256_BLOCK_SIZE);
  cudaMemcpy(cuda_indata, in, inlen * n_batch, cudaMemcpyHostToDevice);
  cudaMalloc(&cuda_result, SHA256_BLOCK_SIZE);
  cudaMemcpy(cuda_result, result, SHA256_BLOCK_SIZE, cudaMemcpyHostToDevice);

  WORD thread = 256;
  WORD block = (n_batch + thread - 1) / thread;

  kernel_sha256_hash<<<block, thread>>>(cuda_indata, inlen, cuda_outdata,
                                        n_batch, cuda_result);
  cudaMemcpy(out, cuda_outdata, SHA256_BLOCK_SIZE, cudaMemcpyDeviceToHost);
  cudaDeviceSynchronize();
  cudaError_t error = cudaGetLastError();
  if (error != cudaSuccess) {
    printf("Error cuda sha256 hash: %s \n", cudaGetErrorString(error));
  }
  cudaFree(cuda_indata);
  cudaFree(cuda_outdata);
  cudaFree(cuda_result);
}
}

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

#define MAX_PASSWORD_LENGTH 40

int main(int argc, char **argv) {
  char *wordlist;
  FILE *file = fopen(argv[1], "r");
  assert(file != NULL);

  // Get the size of the file
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  rewind(file);

  wordlist = (char *)malloc(file_size * sizeof(char));
  assert(wordlist != NULL);

  size_t bytes_read = fread(wordlist, sizeof(char), file_size, file);

  fclose(file);

  char output[MAX_PASSWORD_LENGTH + 1 + SHA256_BLOCK_SIZE];
  output[0] = '\0';

  assert(strlen(argv[2]) == SHA256_BLOCK_SIZE * 2);
  char result[SHA256_BLOCK_SIZE];
  load_hex(argv[2], result);

  int n_batch = bytes_read / (MAX_PASSWORD_LENGTH + 1);
  printf("Batch count: %d\n", n_batch);

  mcm_cuda_sha256_hash_batch((unsigned char *)wordlist, 40,
                             (unsigned char *)output, n_batch, result);

  printf("The password is: %s\n", output);

  return 0;
}