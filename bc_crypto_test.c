/**
 * 300‑line TCC‑compatible implementation of RFC 8439 (ChaCha20‑Poly1305)
 * Build: tcc -o bc_crypto_test bc_crypto_test.c
 *
 * ## Credits & Attribution
 * - Cryptography Engine: Extracted from BearSSL (https://bearssl.org)
 * Original author: Thomas Pornin <pornin@bolet.org>
 *
 * - Test Harness & Formatting:
 * Coded by Gemini 3 Flash and Microsoft Copilot AIs.
 * (Note: The original BearSSL author is NOT responsible for this harness.)
 *
 * - Test Vectors:
 * Taken by Microsoft Copilot AIs directly from RFC 8439 (IETF ChaCha20‑Poly1305)
 *
 * - Project Guidance & Testing:
 * kalina2026 (human maintainer)
 */

/*
 * --- ORIGINAL CRYPTO CORE LICENSE (MIT) ---
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */ 
 
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* =========================================================================
   CORE CRYPTOGRAPHIC ENGINE
   ========================================================================= */

#ifndef INNER_MIN_H
#define INNER_MIN_H

/* Detect unaligned access support */
#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
    #define BR_LE_UNALIGNED 1
#else
    #define BR_LE_UNALIGNED 0
#endif

typedef union { uint32_t u; unsigned char b[4]; } br_union_u32;

static inline uint32_t br_dec32le(const void *src) {
#if BR_LE_UNALIGNED
    return ((const br_union_u32 *)src)->u;
#else
    const unsigned char *buf = src;
    return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
#endif
}

static inline void br_enc32le(void *dst, uint32_t x) {
#if BR_LE_UNALIGNED
    ((br_union_u32 *)dst)->u = x;
#else
    unsigned char *buf = dst;
    buf[0] = (unsigned char)x; buf[1] = (unsigned char)(x >> 8);
    buf[2] = (unsigned char)(x >> 16); buf[3] = (unsigned char)(x >> 24);
#endif
}

static inline void br_enc64le(void *dst, uint64_t x) {
    unsigned char *buf = dst;
    for (int i = 0; i < 8; i++) buf[i] = (unsigned char)(x >> (i * 8));
}

/* Constant-time helpers */
static inline uint32_t EQ(uint32_t x, uint32_t y) { uint32_t q = x ^ y; q |= -q; return (q >> 31) ^ 1; }
static inline uint32_t GT(uint32_t x, uint32_t y) { uint32_t z = x - y; return (z ^ ((x ^ y) & (x ^ z))) >> 31; }
static inline uint32_t MUX(uint32_t ctl, uint32_t x, uint32_t y) { uint32_t m = -ctl; return (x & m) | (y & ~m); }

#endif

uint32_t br_chacha20_ct_run(const void *key, const void *iv, uint32_t cc, void *data, size_t len) {
    unsigned char *buf = data;
    uint32_t kw[8], ivw[3];
    static const uint32_t CW[] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

    for (int u = 0; u < 8; u++) kw[u] = br_dec32le((const unsigned char *)key + (u << 2));
    for (int u = 0; u < 3; u++) ivw[u] = br_dec32le((const unsigned char *)iv + (u << 2));

    while (len > 0) {
        uint32_t state[16];
        unsigned char tmp[64];
        memcpy(&state[0], CW, sizeof CW);
        memcpy(&state[4], kw, sizeof kw);
        state[12] = cc;
        memcpy(&state[13], ivw, sizeof ivw);

#define QROUND(a, b, c, d) do { \
    state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] << 16) | (state[d] >> 16); \
    state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] << 12) | (state[b] >> 20); \
    state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] <<  8) | (state[d] >> 24); \
    state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] <<  7) | (state[b] >> 25); \
} while (0)

        for (int i = 0; i < 10; i++) {
            QROUND(0, 4, 8, 12); QROUND(1, 5, 9, 13); QROUND(2, 6, 10, 14); QROUND(3, 7, 11, 15);
            QROUND(0, 5, 10, 15); QROUND(1, 6, 11, 12); QROUND(2, 7, 8, 13); QROUND(3, 4, 9, 14);
        }
#undef QROUND

        for (int u = 0; u < 4; u++) br_enc32le(&tmp[u << 2], state[u] + CW[u]);
        for (int u = 4; u < 12; u++) br_enc32le(&tmp[u << 2], state[u] + kw[u - 4]);
        br_enc32le(&tmp[48], state[12] + cc);
        for (int u = 13; u < 16; u++) br_enc32le(&tmp[u << 2], state[u] + ivw[u - 13]);

        size_t clen = len < 64 ? len : 64;
        for (size_t u = 0; u < clen; u++) buf[u] ^= tmp[u];
        buf += clen; len -= clen; cc++;
    }
    return cc;
}

static void poly1305_inner(uint32_t *acc, const uint32_t *r, const void *data, size_t len) {
    const unsigned char *buf = data;
    uint32_t a0 = acc[0], a1 = acc[1], a2 = acc[2], a3 = acc[3], a4 = acc[4];
    uint32_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
    uint32_t u1 = r1 * 5, u2 = r2 * 5, u3 = r3 * 5, u4 = r4 * 5;

    while (len > 0) {
        uint64_t w0, w1, w2, w3, w4, c;
        unsigned char tmp[16];
        if (len < 16) {
            memset(tmp, 0, sizeof tmp); memcpy(tmp, buf, len);
            buf = tmp; len = 16;
        }
        a0 += br_dec32le(buf) & 0x03FFFFFF;
        a1 += (br_dec32le(buf + 3) >> 2) & 0x03FFFFFF;
        a2 += (br_dec32le(buf + 6) >> 4) & 0x03FFFFFF;
        a3 += (br_dec32le(buf + 9) >> 6) & 0x03FFFFFF;
        a4 += (br_dec32le(buf + 12) >> 8) | 0x01000000;

#define M(x, y) ((uint64_t)(x) * (uint64_t)(y))
        w0 = M(a0, r0) + M(a1, u4) + M(a2, u3) + M(a3, u2) + M(a4, u1);
        w1 = M(a0, r1) + M(a1, r0) + M(a2, u4) + M(a3, u3) + M(a4, u2);
        w2 = M(a0, r2) + M(a1, r1) + M(a2, r0) + M(a3, u4) + M(a4, u3);
        w3 = M(a0, r3) + M(a1, r2) + M(a2, r1) + M(a3, r0) + M(a4, u4);
        w4 = M(a0, r4) + M(a1, r3) + M(a2, r2) + M(a3, r1) + M(a4, r0);
#undef M
        c = w0 >> 26; a0 = (uint32_t)w0 & 0x3FFFFFF; w1 += c;
        c = w1 >> 26; a1 = (uint32_t)w1 & 0x3FFFFFF; w2 += c;
        c = w2 >> 26; a2 = (uint32_t)w2 & 0x3FFFFFF; w3 += c;
        c = w3 >> 26; a3 = (uint32_t)w3 & 0x3FFFFFF; w4 += c;
        c = w4 >> 26; a4 = (uint32_t)w4 & 0x3FFFFFF;
        a0 += (uint32_t)c * 5; a1 += a0 >> 26; a0 &= 0x3FFFFFF;
        buf += 16; len -= 16;
    }
    acc[0] = a0; acc[1] = a1; acc[2] = a2; acc[3] = a3; acc[4] = a4;
}

typedef uint32_t (*br_chacha20_run)(const void *key, const void *iv, uint32_t cc, void *data, size_t len);

void br_poly1305_ctmul_run(const void *key, const void *iv, void *data, size_t len, const void *aad, size_t aad_len, void *tag, br_chacha20_run ichacha, int encrypt) {
    unsigned char pkey[32], foot[16];
    uint32_t r[5], acc[5], cc, ctl;
    uint64_t w;

    memset(pkey, 0, sizeof pkey);
    ichacha(key, iv, 0, pkey, sizeof pkey);
    if (encrypt) ichacha(key, iv, 1, data, len);

    r[0] = br_dec32le(pkey) & 0x03FFFFFF;
    r[1] = (br_dec32le(pkey + 3) >> 2) & 0x03FFFF03;
    r[2] = (br_dec32le(pkey + 6) >> 4) & 0x03FFC0FF;
    r[3] = (br_dec32le(pkey + 9) >> 6) & 0x03F03FFF;
    r[4] = (br_dec32le(pkey + 12) >> 8) & 0x000FFFFF;

    memset(acc, 0, sizeof acc);
    br_enc64le(foot, (uint64_t)aad_len);
    br_enc64le(foot + 8, (uint64_t)len);
    poly1305_inner(acc, r, aad, aad_len);
    poly1305_inner(acc, r, data, len);
    poly1305_inner(acc, r, foot, sizeof foot);

    cc = 0;
    for (int i = 1; i <= 6; i++) {
        int j = (i >= 5) ? i - 5 : i;
        acc[j] += cc; cc = acc[j] >> 26; acc[j] &= 0x03FFFFFF;
    }
    ctl = GT(acc[0], 0x03FFFFFA);
    for (int i = 1; i < 5; i++) ctl &= EQ(acc[i], 0x03FFFFFF);
    cc = 5;
    for (int i = 0; i < 5; i++) {
        uint32_t t = (acc[i] + cc);
        cc = t >> 26; t &= 0x03FFFFFF;
        acc[i] = MUX(ctl, t, acc[i]);
    }

    w = (uint64_t)acc[0] + ((uint64_t)acc[1] << 26) + br_dec32le(pkey + 16);
    br_enc32le(tag, (uint32_t)w);
    w = (w >> 32) + ((uint64_t)acc[2] << 20) + br_dec32le(pkey + 20);
    br_enc32le((unsigned char *)tag + 4, (uint32_t)w);
    w = (w >> 32) + ((uint64_t)acc[3] << 14) + br_dec32le(pkey + 24);
    br_enc32le((unsigned char *)tag + 8, (uint32_t)w);
    br_enc32le((unsigned char *)tag + 12, (uint32_t)(w >> 32) + (acc[4] << 8) + br_dec32le(pkey + 28));

    if (!encrypt) ichacha(key, iv, 1, data, len);
}

/* =========================================================================
   TEST SUITE (RFC 8439 COMPLIANT)
   ========================================================================= */

static void dump_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("  %-8s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x ", buf[i]);
    printf("\n");
}

static int check(const char *name, const uint8_t *got, const uint8_t *exp, size_t len) {
    if (memcmp(got, exp, len) == 0) {
        printf("[ OK ] %s\n", name);
        return 0;
    } else {
        printf("[FAIL] %s\n", name);
        dump_hex("Expected", exp, len);
        dump_hex("Got", got, len);
        return 1;
    }
}

/**
 * RFC 8439 Section 2.4.2 Test Vector
 */
int test_chacha20_cipher() {
    uint8_t key[32] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    uint8_t nonce[16] = {0,0,0,0, 0,0,0,0x4a, 0,0,0,0, 0,0,0,0};
    uint8_t pt[114] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,0x74,0x2e
    };
    uint8_t exp_ct[114] = {
        0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8,0x07,0xca,0x0d,0xbf,0x50,0x0d,0x6a,0x61,0x56,0xa3,0x8e,0x08,0x8a,0x22,0xb6,0x5e,0x52,0xbc,0x51,0x4d,0x16,0xcc,0xf8,0x06,0x81,0x8c,0xe9,0x1a,0xb7,0x79,0x37,0x36,0x5a,0xf9,0x0b,0xbf,0x74,0xa3,0x5b,0xe6,0xb4,0x0b,0x8e,0xed,0xf2,0x78,0x5e,0x42,0x87,0x4d
    };

    uint8_t buf[114];
    memcpy(buf, pt, 114);
    br_chacha20_ct_run(key, nonce, 1, buf, 114);
    return check("ChaCha20 RFC 2.4.2 Encryption", buf, exp_ct, 114);
}

/**
 * RFC 8439 Section 2.8.2 Test Vector
 */
int test_aead_combined() {
    uint8_t key[32];
    for(int i=0; i<32; i++) key[i] = 0x80 + i;
    uint8_t nonce[16] = {0x07,0,0,0, 0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47, 0,0,0,0};
    uint8_t aad[12] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    uint8_t pt[114] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,0x74,0x2e
    };
    uint8_t exp_ct[114] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,0x61,0x16
    };
    uint8_t exp_tag[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
    };

    uint8_t buf[114], tag[16];
    memcpy(buf, pt, 114);
    br_poly1305_ctmul_run(key, nonce, buf, 114, aad, 12, tag, br_chacha20_ct_run, 1);
    
    int err = 0;
    err |= check("AEAD Ciphertext (RFC 2.8.2)", buf, exp_ct, 114);
    err |= check("AEAD Authentication Tag", tag, exp_tag, 16);
    return err;
}

int main(void) {
    printf("--- RFC 8439 Cryptographic Test Suite ---\n\n");
    
    int failed = 0;
    failed += test_chacha20_cipher();
    failed += test_aead_combined();

    printf("\n--- Result: %s ---\n", failed == 0 ? "PASSED ALL TESTS" : "FAILED TESTS");
    return failed ? 1 : 0;
}
