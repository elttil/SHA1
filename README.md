# SHA1 Implementation

A implementation of SHA1 written in C licensed under BSD-2-Clause.

# Functions
```C
void SHA1_Init(SHA1_CTX *ctx);
void SHA1_Update(SHA1_CTX *ctx, const void *data, size_t len);
void SHA1_Final(SHA1_CTX *ctx, unsigned char *message_digest);
```

# Example code

```C
// SPDX-License-Identifier: 0BSD
#include "sha1.h"
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "No argument supplied.\n");
    return 1;
  }
  uint32_t md[5];
  SHA1_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, argv[1], strlen(argv[1]));
  SHA1_Final(&ctx, (unsigned char*)md);
  printf("%08x%08x%08x%08x%08x", md[0], md[1], md[2], md[3], md[4]);
  return 0;
}
```

# Testing

The code has been tested against the test vectors that have been
published by NIST in [this](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha_all.pdf)
document. It has also been tested by other known SHA1 implementations
with random values as input.
