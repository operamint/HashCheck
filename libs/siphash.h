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

#include <stdint.h>
#include <string.h>

#ifdef _MSC_VER
    #define SH_INLINE __forceinline
#else
    #define SH_INLINE inline
#endif

typedef unsigned long long SH_U64;

#if defined(_WIN32) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    inline SH_U64 _siphash_le64_to_host(SH_U64 x) { return x; }
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    inline SH_U64 _siphash_le64_to_host(SH_U64 x) { return OSSwapLittleToHostInt64(x); }
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
    #include <sys/endian.h>
    inline SH_U64 _siphash_le64_to_host(SH_U64 x) { return letoh64(x); }
#elif defined(__linux__) || defined(__CYGWIN__) || defined(__GNUC__) || defined(__GNU_LIBRARY__)
    #include <endian.h>
    inline SH_U64 _siphash_le64_to_host(SH_U64 x) { return le64toh(x); }
#else
    #error "Unsupported platform.  Cannot determine byte order."    
#endif


typedef struct SipHashState {
    int c, d;
    size_t length;
    SH_U64 padding, v0, v1, v2, v3;
} SipHashState;


SH_INLINE void siphash_init_c_d(SipHashState* s, const SH_U64 key[2], int c, int d) {
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
SH_INLINE void siphash_init(SipHashState* s, const SH_U64 key[2]) {
    siphash_init_c_d(s, key, 2, 4);
}
SH_INLINE void siphash_init13(SipHashState* s, const SH_U64 key[2]) {
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
        SH_U64 _m = m;\
        s->v3 ^= _m;\
        _siphash_compress(rounds, s);\
        s->v0 ^= _m;\
    }

SH_INLINE void siphash_update(SipHashState* s, const void* bytes, size_t size) {
    union { const uint8_t* u8; const SH_U64* u64; } in;
    in.u8 = (const uint8_t*) bytes;
    size_t offset = s->length & 7;
    s->length += size;

    if (offset) {
        size_t end = offset + size;
        size -= 8 - offset;
        while (offset < end && offset < 8) {
            s->padding |= ((SH_U64) *in.u8++) << (offset++ << 3);
        }
        if (end < 8) return;

        _siphash_digest(s->c, s, s->padding);
        s->padding = 0;
    }
    size_t n_words = size >> 3;
    SH_U64 m;

    while (n_words--) {
        memcpy(&m, in.u64++, 8);
        _siphash_digest(s->c, s, _siphash_le64_to_host(m));
    }

    switch (s->length & 7) {
        case 7: s->padding |= ((SH_U64) in.u8[6]) << 48;
        case 6: s->padding |= ((SH_U64) in.u8[5]) << 40;
        case 5: s->padding |= ((SH_U64) in.u8[4]) << 32;
        case 4: s->padding |= ((SH_U64) in.u8[3]) << 24;
        case 3: s->padding |= ((SH_U64) in.u8[2]) << 16;
        case 2: s->padding |= ((SH_U64) in.u8[1]) << 8;
        case 1: s->padding |= ((SH_U64) in.u8[0]);
    }
}

SH_INLINE SH_U64 siphash_finalize(SipHashState* s) {
    _siphash_digest(s->c, s, s->padding | (s->length << 56));

    s->v2 ^= 0xff;
    _siphash_compress(s->d, s);

    return s->v0 ^ s->v1 ^ s->v2 ^ s->v3;
}

SH_INLINE SH_U64 siphash_hash_c_d(const SH_U64 key[2], const void* bytes, const SH_U64 size, int c, int d) {
    SipHashState state;
    siphash_init_c_d(&state, key, c, d);
    siphash_update(&state, bytes, size);
    return siphash_finalize(&state);
}
// default
SH_INLINE SH_U64 siphash_hash(const SH_U64 key[2], const void* bytes, const SH_U64 size) {
    return siphash_hash_c_d(key, bytes, size, 2, 4);
}
SH_INLINE SH_U64 siphash_hash13(const SH_U64 key[2], const void* bytes, const SH_U64 size) {
    return siphash_hash_c_d(key, bytes, size, 1, 3);
}


#endif
