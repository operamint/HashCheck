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

#ifndef FREEWAYHASH_SIP_HASH_H_
#define FREEWAYHASH_SIP_HASH_H_

// Portable, very fast standalone C++ SipHash implementation.
//
// freewayhash::SipHash is aproximately 1.7x - 1.2x faster than current
// highwayhash::SipHash for message lenghts 8 - 64. Equal speed for long messages.
// Tested with VS2017 15.9.15 and GNU g++ 5.1.0 compilers on Windows.
// Ref https://github.com/google/highwayhash
// 
// freewayhash::SipHash13 is aproximately 2.0x - 1.2x faster than current
// highwayhash::SipHash13 for message lenghts 8 - 64. Equal speed for long messages. 
// 
// The implementation is streaming-capable, meaning it can incrementally compute
// a hash by multiple calls to Update() before Finalize() with arbitrary data sizes.

#include <cstdint>
#include <cstring>

#ifdef _MSC_VER
    #define HH_INLINE __forceinline
#else
    #define HH_INLINE inline
#endif

namespace freewayhash {

    using HH_U64 = unsigned long long;
    using std::uint8_t;
    using std::size_t;

    template <int bits> HH_INLINE HH_U64 RotateLeft(HH_U64 x) {
        return (x << bits) | (x >> (64 - bits));
    }
    template <int u, int v> HH_INLINE void HalfRound(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) {
        a += b;
        c += d;
        b = RotateLeft<u>(b) ^ a;
        d = RotateLeft<v>(d) ^ c;
        a = RotateLeft<32>(a);
    }
    HH_U64 Le64ToHost(HH_U64);
}

#if defined(_WIN32) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    inline freewayhash::HH_U64 freewayhash::Le64ToHost(HH_U64 x) { return x; }
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    inline freewayhash::HH_U64 freewayhash::Le64ToHost(HH_U64 x) { return OSSwapLittleToHostInt64(x); }
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
    #include <sys/endian.h>
    inline freewayhash::HH_U64 freewayhash::Le64ToHost(HH_U64 x) { return letoh64(x); }
#elif defined(__linux__) || defined(__CYGWIN__) || defined(__GNUC__) || defined(__GNU_LIBRARY__)
    #include <endian.h>
    inline freewayhash::HH_U64 freewayhash::Le64ToHost(HH_U64 x) { return le64toh(x); }
#else
    #error "Unsupported platform.  Cannot determine byte order."    
#endif


namespace freewayhash {

    struct SipKey {
        HH_U64 key[2];
        operator const HH_U64*() const { return key; }

        static HH_INLINE SipKey FromStr(const char str[16]) {
            return SipKey{Le64ToHost(*reinterpret_cast<const HH_U64*>(str)), 
                          Le64ToHost(*reinterpret_cast<const HH_U64*>(str + 8))};
        }
    };

    // SipHashState API.

    template <int kUpdateIters = 2, int kFinalizeIters = 4> class SipHashState {
        size_t mLength;
        HH_U64 mPadding, v0, v1, v2, v3;

    public:
        using Key = HH_U64[2];

        explicit HH_INLINE SipHashState(const HH_U64 key[2]) :
            mLength(0),
            mPadding(0),
            v0(key[0] ^ 0x736f6d6570736575),
            v1(key[1] ^ 0x646f72616e646f6d),
            v2(key[0] ^ 0x6c7967656e657261),
            v3(key[1] ^ 0x7465646279746573) {
        }

        HH_INLINE void Update(const void* bytes, size_t size) {
            union { const uint8_t* in_u8; const HH_U64* in_u64; const void* in; };
            in = bytes;
            size_t offset = mLength & 7;
            mLength += size;

            if (offset) {
                size_t end = offset + size;
                size -= 8 - offset;
                while (offset < end && offset < 8) {
                    mPadding |= HH_U64(*in_u8++) << (offset++ << 3);
                }
                if (end < 8) return;

                Digest<kUpdateIters>(mPadding);
                mPadding = 0;
            }
            size_t n_words = size >> 3;
            HH_U64 m;

            while (n_words--) {
                std::memcpy(&m, in_u64++, 8);
                Digest<kUpdateIters>(Le64ToHost(m));
            }

            switch (mLength & 7) {
                case 7: mPadding |= HH_U64(in_u8[6]) << 48;
                case 6: mPadding |= HH_U64(in_u8[5]) << 40;
                case 5: mPadding |= HH_U64(in_u8[4]) << 32;
                case 4: mPadding |= HH_U64(in_u8[3]) << 24;
                case 3: mPadding |= HH_U64(in_u8[2]) << 16;
                case 2: mPadding |= HH_U64(in_u8[1]) << 8;
                case 1: mPadding |= HH_U64(in_u8[0]);
            }
        }

        template <typename ContiguousContainer>
        HH_INLINE void Update(const ContiguousContainer& container) {
            Update(container.data(), container.size() * sizeof(typename ContiguousContainer::value_type));
        }

        HH_INLINE HH_U64 Finalize() {
            Digest<kUpdateIters>(mPadding | (mLength << 56));

            v2 ^= 0xff;
            Compress<kFinalizeIters>();

            return v0 ^ v1 ^ v2 ^ v3;
        }

    private:
        template <int rounds> HH_INLINE void Compress() {
            for (int i = 0; i < rounds; ++i) {
                HalfRound<13, 16>(v0, v1, v2, v3);
                HalfRound<17, 21>(v2, v1, v0, v3);
            }
        }

        template <int rounds> HH_INLINE void Digest(HH_U64 m) {
            v3 ^= m;
            Compress<rounds>();
            v0 ^= m;
        }
    };

    // highwayhash-like API:

    template <int kUpdateIters = 2, int kFinalizeIters = 4>
    HH_INLINE HH_U64 SipHash(const HH_U64 key[2], const void* bytes, const HH_U64 size) {
        SipHashState<kUpdateIters, kFinalizeIters> state(key);
        state.Update(bytes, size);
        return state.Finalize();
    }

    template <int kUpdateIters = 2, int kFinalizeIters = 4, typename ContiguousContainer>
    HH_INLINE HH_U64 SipHash(const HH_U64 key[2], const ContiguousContainer& container) {
        SipHashState<kUpdateIters, kFinalizeIters> state(key);
        state.Update(container);
        return state.Finalize();        
    }

    using SipHash13State = SipHashState<1, 3>;

    HH_INLINE HH_U64 SipHash13(const HH_U64 key[2], const void* bytes, const HH_U64 size) {
        return SipHash<1, 3>(key, bytes, size);
    }
}

#endif
