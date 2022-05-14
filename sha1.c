//
// Copyright (C) 2022 by Anton Kling <anton@kling.gg>
//
// SPDX-License-Identifier: BSD-2-Clause
//
#include "sha1.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SHA1_CONSTANT_H0 0x67452301
#define SHA1_CONSTANT_H1 0xefcdab89
#define SHA1_CONSTANT_H2 0x98badcfe
#define SHA1_CONSTANT_H3 0x10325476
#define SHA1_CONSTANT_H4 0xc3d2e1f0

void SHA1_Init(SHA1_CTX *ctx) {
  // 6.1.1 SHA-1 Preprocessing

  // 1. Set the initial hash value, H(0), as specified in Sec. 5.3.1
  ctx->h[0] = SHA1_CONSTANT_H0;
  ctx->h[1] = SHA1_CONSTANT_H1;
  ctx->h[2] = SHA1_CONSTANT_H2;
  ctx->h[3] = SHA1_CONSTANT_H3;
  ctx->h[4] = SHA1_CONSTANT_H4;

  ctx->len = ctx->active_len = 0;

  memset(ctx->block, 0, BLOCK_BYTES);
}

uint32_t reverse_32(uint32_t _value) {
  return (((_value & 0x000000FF) << 24) | ((_value & 0x0000FF00) << 8) |
          ((_value & 0x00FF0000) >> 8) | ((_value & 0xFF000000) >> 24));
}

void pad_sha1_message(uint8_t *M, size_t l, size_t active_l, uint8_t *block) {
  // FIXME: Use a secure function. Not memset
  memset(block, 0, 1024 / 8);
  memcpy(block, M, active_l / 8);

#define ARRAY_NUM(_loc) (((_loc) / 8) + !(0 == ((_loc) % 8)))

  // 5. PREPROCESSING

  // 5.1.1 SHA-1, SHA-224 and SHA-256

  // Append the bit “1” to the end of the message
  block[ARRAY_NUM(active_l)] = 1 << 7;

  // followed by k zero bits, where k is the smallest, non-negative
  // solution to the equation 'l + 1 + k \cong 448 mod 512'
  int k;
  uint64_t rest = (active_l + 1) % 512;
  if (rest < 448)
    k = 448 - rest;
  else
    k = 512 - rest + 448;

  memset(block + ARRAY_NUM(active_l) + 2, 0x0, k / 8);

  // Then append the 64-bit block that is equal to the number 'l' expressed
  // using a binary representatio
  uint64_t *final_64bit_block;
  final_64bit_block =
      (uint64_t *)(block + active_l / 8 + k / 8 + 1 + sizeof(uint32_t));

  *(final_64bit_block - sizeof(uint32_t)) = reverse_32(l >> 32);
  *(final_64bit_block) = reverse_32(l & 0xFFFFFFFF);
}

uint32_t sha1_f(uint8_t t, uint32_t x, uint32_t y, uint32_t z) {
  if (t <= 19) {
    // Ch(x,y,z)
    return (x & y) ^ ((~x) & z);
  }
  if (t <= 39 || t >= 60) {
    // Parity(x,y,z)
    return x ^ y ^ z;
  }
  if (t <= 59) {
    // Maj(x,y,z)
    return (x & y) ^ (x & z) ^ (y & z);
  }
  assert(0);
}

uint32_t sha1_get_k(uint8_t t) {
  if (t <= 19)
    return 0x5a827999;
  if (t <= 39)
    return 0x6ed9eba1;
  if (t <= 59)
    return 0x8f1bbcdc;
  if (t <= 79)
    return 0xca62c1d6;
  assert(0);
}

uint32_t ROTL(uint32_t value, uint8_t shift) {
  uint32_t rotated = value << shift;
  uint32_t did_overflow = value >> (32 - shift);
  return (rotated | did_overflow);
}

void add_block(SHA1_CTX *ctx, uint8_t *_block) {
  uint32_t *block = (uint32_t *)_block;
  for (size_t i = 0; i < 16; i++)
    block[i] = reverse_32(block[i]);

  uint32_t W[80];
  uint32_t a, b, c, d, e;
  uint32_t *M = block;

  // 1. Prepare the message schedule, {Wt}:
  for (size_t t = 0; t < 16; t++)
    W[t] = M[t];

  for (size_t t = 16; t < 80; t++) {
    // ROTL(1)(W(t-3) ^ W(t-8) ^ W(t-16))
    W[t] = ROTL((W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]), 1);
  }

  // 2. Initialize the five working variables, a, b, c, d, and e, with the
  // (i-1)^(st) hash value:
  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];
  e = ctx->h[4];

  // 3. For t=0 to 79:
  for (size_t t = 0; t < 80; t++) {
    uint32_t T = ROTL(a, 5) + sha1_f(t, b, c, d) + e + sha1_get_k(t) + W[t];
    e = d;
    d = c;
    c = ROTL(b, 30);
    b = a;
    a = T;
  }

  // 4. Compute the ith intermediate hash value H(i):
  ctx->h[0] = a + ctx->h[0];
  ctx->h[1] = b + ctx->h[1];
  ctx->h[2] = c + ctx->h[2];
  ctx->h[3] = d + ctx->h[3];
  ctx->h[4] = e + ctx->h[4];
}

void SHA1_Final(SHA1_CTX *ctx, unsigned char *message_digest) {
  uint8_t block[BLOCK_BYTES * 2] = {0};
  pad_sha1_message(ctx->block, ctx->len * 8, ctx->active_len * 8, block);

  add_block(ctx, block);

  if (((ctx->active_len * 8 + 1) % 512) >= 448)
    add_block(ctx, block + BLOCK_BYTES);

  for (size_t i = 0; i < 5; i++)
    memcpy(message_digest + sizeof(uint32_t) * i, &ctx->h[i], sizeof(uint32_t));
}

void SHA1_Update(SHA1_CTX *ctx, const void *data, size_t len) {
  size_t write_len =
      ((ctx->active_len + len) > BLOCK_BYTES) ? (BLOCK_BYTES-ctx->active_len) : len;

  memcpy(ctx->block + ctx->active_len, data, write_len);
  ctx->len += write_len;
  ctx->active_len += write_len;
  if (BLOCK_BYTES != ctx->active_len)
    return;

  add_block(ctx, ctx->block);
  memset(ctx->block, 0, BLOCK_BYTES);
  ctx->active_len = 0;

  if (len > write_len) {
    len -= write_len;
    data += write_len;
    return SHA1_Update(ctx, data, len);
  }
}
