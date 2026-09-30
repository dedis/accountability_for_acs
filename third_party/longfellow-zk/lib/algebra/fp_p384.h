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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_P384_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_P384_H_

#include <array>
#include <cstdint>

#include "algebra/fp_generic.h"
#include "algebra/nat.h"
#include "algebra/sysdep.h"

namespace proofs {
// Optimized implementation of
// Fp(39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319)
// 2^384 - 2^128 - 2^96 + 2^32 - 1

struct Fp384Reduce {
  // Hardcoded base_64 modulus.
  static const constexpr std::array<uint64_t, 6> kModulus = {
      0x00000000ffffffffu, 0xffffffff00000000u, 0xfffffffffffffffeu,
      0xffffffffffffffffu, 0xffffffffffffffffu, 0xffffffffffffffffu};

  static inline void reduction_step(uint64_t a[], uint64_t mprime,
                                    const Nat<6>& m) {
    // mprime = 2^32 + 1
    uint64_t r = ((1ull << 32) + 1) * a[0];
    // p = 2^384 - 2^128 - 2^96 + 2^32 - 1
    uint64_t h[7] = {r << 32, r >> 32, 0, 0, 0, 0, r};
    accum(8, a, 7, h);

    uint64_t l[4] = {r, r << 32, r >> 32, 0};  // - 2^96 - 1
    uint64_t l128[1] = {r};
    accum(2, l+2, 1, l128);   // - 2^128 to l, with carry
    negaccum(8, a, 4, l);
  }

  static inline void reduction_step(uint32_t a[], uint32_t mprime,
                                    const Nat<6>& m) {
    uint32_t r = mprime * a[0];
    uint32_t h[13] = {0, r, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, r};
    accum(14, a, 13, h);

    uint32_t l[5] = {r, 0, 0, r, r};
    negaccum(14, a, 5, l);
  }
};

template <bool optimized_mul = false>
using Fp384 = FpGeneric<6, optimized_mul, Fp384Reduce>;
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_P384_H_
