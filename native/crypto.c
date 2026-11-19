/* SHA-256 (FIPS 180-4), HMAC-SHA-256 (RFC 2104) and IETF ChaCha20 (RFC 8439), no libc/heap. */
#include "crypto.h"

static u32 ror(u32 x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static u32 rol(u32 x, unsigned n) { return (x << n) | (x >> (32 - n)); }
static u32 le32(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static const u32 K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha_block(u32 h[8], const u8 block[64]) {
    u32 w[64];
    for (unsigned i = 0; i < 16; ++i)
        w[i] = ((u32)block[4*i] << 24) | ((u32)block[4*i+1] << 16)
             | ((u32)block[4*i+2] << 8) | block[4*i+3];
    for (unsigned i = 16; i < 64; ++i) {
        u32 a = w[i-15], b = w[i-2];
        w[i] = w[i-16] + (ror(a,7)^ror(a,18)^(a>>3)) + w[i-7]
             + (ror(b,17)^ror(b,19)^(b>>10));
    }
    u32 a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],v=h[7];
    for (unsigned i = 0; i < 64; ++i) {
        u32 t1=v+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^(~e&g))+K[i]+w[i];
        u32 t2=(ror(a,2)^ror(a,13)^ror(a,22))+((a&b)^(a&c)^(b&c));
        v=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=v;
}

void p3_sha256_init(struct p3_sha256_ctx *ctx) {
    static const u32 iv[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    for (unsigned i = 0; i < 8; ++i) ctx->h[i] = iv[i];
    for (unsigned i = 0; i < 64; ++i) ctx->buf[i] = 0;
    ctx->used = 0;
    ctx->total = 0;
}

void p3_sha256_update(struct p3_sha256_ctx *ctx, const u8 *data, usize size) {
    ctx->total += (u64)size;
    while (size > 0) {
        if (ctx->used == 0 && size >= 64) {
            sha_block(ctx->h, data);
            data += 64;
            size -= 64;
        } else {
            usize take = 64 - ctx->used;
            if (take > size) take = size;
            for (usize i = 0; i < take; ++i) ctx->buf[ctx->used + i] = data[i];
            ctx->used += take;
            data += take;
            size -= take;
            if (ctx->used == 64) {
                sha_block(ctx->h, ctx->buf);
                ctx->used = 0;
            }
        }
    }
}

void p3_sha256_final(struct p3_sha256_ctx *ctx, u8 out[32]) {
    u8 last[64];
    for (unsigned i = 0; i < 64; ++i) last[i] = i < ctx->used ? ctx->buf[i] : 0;
    last[ctx->used] = 0x80;
    if (ctx->used >= 56) {
        sha_block(ctx->h, last);
        for (unsigned i = 0; i < 64; ++i) last[i] = 0;
    }
    u64 bits = ctx->total * 8;
    for (unsigned i = 0; i < 8; ++i) last[63 - i] = (u8)(bits >> (i * 8));
    sha_block(ctx->h, last);
    for (unsigned i = 0; i < 8; ++i)
        for (unsigned j = 0; j < 4; ++j)
            out[4*i + j] = (u8)(ctx->h[i] >> (24 - j * 8));
}

void p3_sha256(const u8 *data, usize size, u8 out[32]) {
    struct p3_sha256_ctx ctx;
    p3_sha256_init(&ctx);
    p3_sha256_update(&ctx, data, size);
    p3_sha256_final(&ctx, out);
}

void p3_hmac_sha256(const u8 *key, usize ksize, const u8 *data, usize dsize, u8 out[32]) {
    u8 kblock[64];
    for (unsigned i = 0; i < 64; ++i) kblock[i] = 0;
    if (ksize > 64) {
        p3_sha256(key, ksize, kblock);
    } else {
        for (usize i = 0; i < ksize; ++i) kblock[i] = key[i];
    }
    u8 ipad[64], opad[64], inner[32];
    for (unsigned i = 0; i < 64; ++i) {
        ipad[i] = kblock[i] ^ 0x36;
        opad[i] = kblock[i] ^ 0x5c;
    }
    struct p3_sha256_ctx ctx;
    p3_sha256_init(&ctx);
    p3_sha256_update(&ctx, ipad, 64);
    p3_sha256_update(&ctx, data, dsize);
    p3_sha256_final(&ctx, inner);

    p3_sha256_init(&ctx);
    p3_sha256_update(&ctx, opad, 64);
    p3_sha256_update(&ctx, inner, 32);
    p3_sha256_final(&ctx, out);

    for (unsigned i = 0; i < 64; ++i) {
        ((volatile u8 *)kblock)[i] = 0;
        ((volatile u8 *)ipad)[i] = 0;
        ((volatile u8 *)opad)[i] = 0;
    }
    for (unsigned i = 0; i < 32; ++i) ((volatile u8 *)inner)[i] = 0;
}

#define QR(a,b,c,d) do { \
    a+=b; d=rol(d^a,16); c+=d; b=rol(b^c,12); \
    a+=b; d=rol(d^a,8); c+=d; b=rol(b^c,7); \
} while(0)

void p3_chacha20_block(const u8 key[32], const u8 nonce[12], u32 counter, u8 out[64]) {
    u32 initial[16]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    for (unsigned i=0;i<8;++i) initial[i+4]=le32(key+4*i);
    initial[12]=counter;
    for (unsigned i=0;i<3;++i) initial[i+13]=le32(nonce+4*i);
    u32 x[16];
    for (unsigned i=0;i<16;++i) x[i]=initial[i];
    for(unsigned i=0;i<10;++i) {
        QR(x[0],x[4],x[8],x[12]);QR(x[1],x[5],x[9],x[13]);
        QR(x[2],x[6],x[10],x[14]);QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]);QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8],x[13]);QR(x[3],x[4],x[9],x[14]);
    }
    for(unsigned i=0;i<16;++i) x[i]+=initial[i];
    for(unsigned i=0;i<64;++i) out[i]=(u8)(x[i/4]>>(8*(i%4)));
    for(unsigned i=0;i<16;++i) {
        ((volatile u32 *)x)[i]=0;
        ((volatile u32 *)initial)[i]=0;
    }
}

void p3_chacha20(u8 *data, usize size, const u8 key[32], const u8 nonce[12], u32 counter) {
    u8 stream[64];
    u32 ctr = counter;
    while(size) {
        p3_chacha20_block(key, nonce, ctr++, stream);
        usize n=size<64?size:64;
        for(usize i=0;i<n;++i) data[i]^=stream[i];
        data+=n;size-=n;
    }
    for(unsigned i=0;i<64;++i) ((volatile u8 *)stream)[i]=0;
}
