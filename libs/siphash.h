// Copyright 2019 operamint (github). All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef _SIPHASH_H_
#define _SIPHASH_H_

// Portable, very fast standalone ANSI C SipHash implementation.

#include <string.h>
#include <limits.h>

typedef unsigned char      sip_uint8_t;
typedef unsigned long long sip_uint64_t;
typedef int sip_uint_size_check[ sizeof(sip_uint64_t) == 8 && CHAR_BIT == 8 ? 1 : -1 ];

#ifdef _MSC_VER
    #define SIP_INLINE __forceinline
#elif defined(__GNUC__)
    #define SIP_INLINE __attribute__((always_inline)) inline
#else
    #define SIP_INLINE inline
#endif

#if defined(_WIN32) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    SIP_INLINE sip_uint64_t sip_le64_to_host(sip_uint64_t x) { return x; }
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    SIP_INLINE sip_uint64_t sip_le64_to_host(sip_uint64_t x) { return OSSwapLittleToHostInt64(x); }
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
    #include <sys/endian.h>
    SIP_INLINE sip_uint64_t sip_le64_to_host(sip_uint64_t x) { return letoh64(x); }
#elif defined(__linux__) || defined(__CYGWIN__) || defined(__GNUC__) || defined(__GNU_LIBRARY__)
    #include <endian.h>
    SIP_INLINE sip_uint64_t sip_le64_to_host(sip_uint64_t x) { return le64toh(x); }
#else
    #error "Unsupported platform.  Cannot determine byte order."    
#endif


typedef struct siphash_state {
    int c, d;
    size_t length;
    sip_uint64_t padding, v0, v1, v2, v3;
} siphash_state;


SIP_INLINE void siphash_init_c_d(siphash_state* s, const sip_uint64_t key[2], const int c, const int d) {
    s->c = c;
    s->d = d;
    s->length = 0;
    s->padding = 0;
    s->v0 = key[0] ^ 0x736f6d6570736575;
    s->v1 = key[1] ^ 0x646f72616e646f6d;
    s->v2 = key[0] ^ 0x6c7967656e657261;
    s->v3 = key[1] ^ 0x7465646279746573;
}

// default
SIP_INLINE void siphash_init(siphash_state* s, const sip_uint64_t key[2]) {
    siphash_init_c_d(s, key, 2, 4);
}
SIP_INLINE void siphash_init13(siphash_state* s, const sip_uint64_t key[2]) {
    siphash_init_c_d(s, key, 1, 3);
}

#define _siphash_rotate_left64(bits, x)\
    ((x << bits) | (x >> (64 - bits)))

#define _siphash_half_round(u, v, a, b, c, d)\
    a += b;\
    c += d;\
    b = _siphash_rotate_left64(u, b) ^ a;\
    d = _siphash_rotate_left64(v, d) ^ c;\
    a = _siphash_rotate_left64(32, a);\

#define _siphash_compress(rounds, s)\
    for (int i = 0; i < rounds; ++i) {\
        _siphash_half_round(13, 16, s->v0, s->v1, s->v2, s->v3);\
        _siphash_half_round(17, 21, s->v2, s->v1, s->v0, s->v3);\
    }

#define _siphash_digest(rounds, s, m) {\
        sip_uint64_t _m = m;\
        s->v3 ^= _m;\
        _siphash_compress(rounds, s);\
        s->v0 ^= _m;\
    }

SIP_INLINE void siphash_update(siphash_state* s, const void* bytes, size_t size) {
    union { const sip_uint8_t* u8; const sip_uint64_t* u64; } in;
    in.u8 = (const sip_uint8_t*) bytes;
    size_t offset = s->length & 7;
    s->length += size;

    if (offset) {
        size_t end = offset + size;
        size -= 8 - offset;
        while (offset < end && offset < 8) {
            s->padding |= ((sip_uint64_t) *in.u8++) << (offset++ << 3);
        }
        if (end < 8) return;

        _siphash_digest(s->c, s, s->padding);
        s->padding = 0;
    }
    size_t n_words = size >> 3;
    sip_uint64_t m;

    while (n_words--) {
        memcpy(&m, in.u64++, 8);
        _siphash_digest(s->c, s, sip_le64_to_host(m));
    }

    switch (s->length & 7) {
        case 7: s->padding |= ((sip_uint64_t) in.u8[6]) << 48;
        case 6: s->padding |= ((sip_uint64_t) in.u8[5]) << 40;
        case 5: s->padding |= ((sip_uint64_t) in.u8[4]) << 32;
        case 4: s->padding |= ((sip_uint64_t) in.u8[3]) << 24;
        case 3: s->padding |= ((sip_uint64_t) in.u8[2]) << 16;
        case 2: s->padding |= ((sip_uint64_t) in.u8[1]) << 8;
        case 1: s->padding |= ((sip_uint64_t) in.u8[0]);
    }
}

SIP_INLINE sip_uint64_t siphash_finalize(siphash_state* s) {
    _siphash_digest(s->c, s, s->padding | (s->length << 56));

    s->v2 ^= 0xff;
    _siphash_compress(s->d, s);

    return s->v0 ^ s->v1 ^ s->v2 ^ s->v3;
}

SIP_INLINE sip_uint64_t siphash_hash_c_d(const sip_uint64_t key[2], const void* bytes, const sip_uint64_t size, const int c, const int d) {
    siphash_state state;
    siphash_init_c_d(&state, key, c, d);
    siphash_update(&state, bytes, size);
    return siphash_finalize(&state);
}

// default
inline sip_uint64_t siphash_hash(const sip_uint64_t key[2], const void* bytes, const sip_uint64_t size) {
    return siphash_hash_c_d(key, bytes, size, 2, 4);
}
inline sip_uint64_t siphash_hash13(const sip_uint64_t key[2], const void* bytes, const sip_uint64_t size) {
    return siphash_hash_c_d(key, bytes, size, 1, 3);
}

#endif
