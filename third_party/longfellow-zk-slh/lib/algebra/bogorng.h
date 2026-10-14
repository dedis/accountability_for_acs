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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_BOGORNG_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_BOGORNG_H_

#include <cstdint>
namespace proofs {
// Totally bogus "random" number generator, used only for testing.
// The public and internal functions of this class all take a const Field&
// parameter to produce random elements in the Field. It is the caller's
// responsibility to ensure the object remains valid during execution.
//
// We are testing mostly with prime fields. Following Knuth, we pick a simple
// multiplier a, with reasonable Hamming weight, and good spectral scores.
// The smallest prime we care about is ~23 bits, so we tune "a" for that.
// For GF2_128, we use the same a*x generator, and have a unit test to ensure
// there are no short loops.
//
// Rank 3: a = 7300988
// Binary: 0b11011110110011101111100
// 2D Spectral Score: 2737.21 (Max theoretical is ~3109)
// 3D Spectral Score: 184.24 (Max theoretical is ~228)
//
// 3d: 184.24
// 3d: 7300988.00 // for > 128-bit field
template <class Field>
class Bogorng {
  using Elt = typename Field::Elt;

 public:
  explicit Bogorng(const Field* F, uint64_t seed = 1234569u,
                   uint64_t mul = 7300988u)
      : f_(F), next_(F->of_scalar_field(seed)), mul_(F->of_scalar_field(mul)) {}

  Elt next() {
    // really old-school
    f_->mul(next_, mul_);
    return next_;
  }

  Elt nonzero() {
    Elt x;
    do {
      x = next();
    } while (x == f_->zero());
    return x;
  }

 private:
  const Field* f_;
  Elt next_;
  Elt mul_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_BOGORNG_H_
