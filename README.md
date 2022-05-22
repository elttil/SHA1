# SHA1 Implementation

A implementation of SHA1 written in C licensed under BSD-2-Clause.

# Functions
```C
void SHA1_Init(SHA1_CTX *ctx);
void SHA1_Update(SHA1_CTX *ctx, const void *data, size_t len);
void SHA1_Final(SHA1_CTX *ctx, unsigned char *message_digest);
```

# Testing

The code has been tested against the test vectors that have been
published by NIST in [this](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha_all.pdf)
document. It has also been tested by other known SHA1 implementations
with random values as input.
