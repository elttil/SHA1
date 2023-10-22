# SHA1 Implementation

A implementation of SHA1 and a HMAC implementation for SHA1 written in
C.

# Functions
```C
void SHA1_Init(SHA1_CTX *ctx);
void SHA1_Update(SHA1_CTX *ctx, const void *data, size_t len);
void SHA1_Final(SHA1_CTX *ctx, unsigned char *message_digest);
void SHA1_HMAC(unsigned char *message, uint64_t message_len, unsigned char *key,
               uint64_t key_len, uint8_t output[SHA1_LEN]);
```

# Testing

The code has been tested against the test vectors that have been
published by NIST in [this](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha_all.pdf)
document. It has also been tested by other known SHA1 implementations
with random values as input.

The HMAC algorithm has been tested with inputs from [rfc2202](https://www.rfc-editor.org/rfc/rfc2202).
