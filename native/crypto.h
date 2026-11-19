#ifndef PROTECT3_CRYPTO_H
#define PROTECT3_CRYPTO_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long usize;

struct p3_sha256_ctx {
    u32 h[8];
    u8 buf[64];
    usize used;
    u64 total;
};

void p3_sha256_init(struct p3_sha256_ctx *ctx);
void p3_sha256_update(struct p3_sha256_ctx *ctx, const u8 *data, usize size);
void p3_sha256_final(struct p3_sha256_ctx *ctx, u8 out[32]);
void p3_sha256(const u8 *data, usize size, u8 out[32]);
void p3_hmac_sha256(const u8 *key, usize ksize, const u8 *data, usize dsize, u8 out[32]);
void p3_chacha20_block(const u8 key[32], const u8 nonce[12], u32 counter, u8 out[64]);
void p3_chacha20(u8 *data, usize size, const u8 key[32], const u8 nonce[12], u32 counter);

#endif
