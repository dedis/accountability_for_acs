// Copyright 2026 Google LLC.
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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_P128_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_P128_H_

#include <array>
#include <cstdint>

#include "algebra/fp_generic.h"
#include "algebra/nat.h"
#include "algebra/sysdep.h"

namespace proofs {
// Optimized implementation of Fp(2^128 - 2^108 + 1).  We call this
// prime P128 because of lack of imagination, but unlike P256,
// this is not a NIST standard name.  The field contains
// roots of unity of order 2^108.

// Root of unity from pari-gp:
// ? p=2^128-2^108+1
// %1 = 340282042402384805036647824275747635201
// ? g=ffgen(x+Mod(1,p))
// %2 = 340282042402384805036647824275747635200
// ? w=sqrtn(g,2^107)
// %3 = 17166008163159356379329005055841088858
//
// ? w=Mod(17166008163159356379329005055841088858, p)
// %4 = Mod(17166008163159356379329005055841088858,
//          340282042402384805036647824275747635201)
// ? w^(2^107)
// %5 = Mod(340282042402384805036647824275747635200,
//          340282042402384805036647824275747635201)
// ? w^(2^108)
// %6 = Mod(1, 340282042402384805036647824275747635201)
//
// Root of unity of order 32:
// ? w32=w^(2^(108-32))
// %15 = Mod(164956748514267535023998284330560247862,
//           340282042402384805036647824275747635201)
// ? w32^(2^31)
// %16 = Mod(340282042402384805036647824275747635200,
//           340282042402384805036647824275747635201)
// ? w32^(2^32)
// %17 = Mod(1, 340282042402384805036647824275747635201)

/*
This struct contains an optimized reduction step for the chosen field.
*/
struct Fp128Reduce {
  // Harcoded base_64 modulus.
  static const constexpr std::array<uint64_t, 2> kModulus = {
      0x0000000000000001u,
      0xFFFFF00000000000u,
  };

  static inline void reduction_step(uint64_t a[], uint64_t mprime,
                                    const Nat<2>& m) {
    uint64_t r = -a[0];
    uint64_t sub[2] = {r << 44, r >> 20};
    uint64_t add[3] = {r, 0, r};
    accum(4, a, 3, add);
    negaccum(3, a + 1, 2, sub);
  }

  static inline void reduction_step(uint32_t a[], uint32_t mprime,
                                    const Nat<2>& m) {
    uint32_t r = -a[0];
    uint32_t sub[2] = {r << 12, r >> 20};
    uint32_t add[5] = {r, 0, 0, 0, r};
    accum(6, a, 5, add);
    negaccum(3, a + 3, 2, sub);
  }
};

template <bool optimized_mul = false>
using Fp128 = FpGeneric<2, optimized_mul, Fp128Reduce>;
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_P128_H_
