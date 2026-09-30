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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_P521_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_P521_H_

#include <array>
#include <cstdint>

#include "algebra/fp_generic.h"
#include "algebra/nat.h"
#include "algebra/sysdep.h"

namespace proofs {
// Optimized implementation of
// Fp(6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151)
// 2^521 - 1

struct Fp521Reduce {
  // Hardcoded base_64 modulus.
  static const constexpr std::array<uint64_t, 9> kModulus = {
      0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFFFFFFFFFFu,
      0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFFFFFFFFFFu,
      0xFFFFFFFFFFFFFFFFu, 0xFFFFFFFFFFFFFFFFu, 0x1FFu};

  static inline void reduction_step(uint64_t a[], uint64_t mprime,
                                    const Nat<9>& m) {
    // p = 2^521 - 1
    // mprime = 1
    uint64_t r = a[0];
    uint64_t l[1] = {r};
    uint64_t h[2] = {r << 9, r >> 55};
    accum(3, a + 8, 2, h);
    negaccum(11, a, 1, l);
  }

  static inline void reduction_step(uint32_t a[], uint32_t mprime,
                                    const Nat<9>& m) {
    uint32_t r = a[0];
    uint32_t l[1] = {r};
    uint32_t h[2] = {r << 9, r >> 23 };
    accum(4, a + 16, 2, h);
    negaccum(20, a, 1, l);
  }
};

template <bool optimized_mul = false>
using Fp521 = FpGeneric<9, optimized_mul, Fp521Reduce>;
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_P521_H_
