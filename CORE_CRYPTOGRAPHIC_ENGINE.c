/**
 * --- CORE_CRYPTOGRAPHIC_ENGINE.c ---
 * TCC‑compatible implementation of RFC 8439 (ChaCha20‑Poly1305)
 *
 * ## Credits & Attribution
 * - Cryptography Engine: Extracted by Gemini 3 Flash from BearSSL (https://bearssl.org)
 * Original author: Thomas Pornin <pornin@bolet.org>
 *
 */
/*
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
