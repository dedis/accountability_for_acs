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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_UNARY_PLUCKER_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_UNARY_PLUCKER_H_
#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "algebra/interpolation.h"
#include "algebra/poly.h"
#include "circuits/logic/bit_plucker_constants.h"
#include "circuits/logic/polynomial.h"

namespace proofs {

template <class Logic, size_t NJ>
class UnaryPlucker {
 public:
  using Field = typename Logic::Field;
  using BitW = typename Logic::BitW;
  using EltW = typename Logic::EltW;
  using Elt = typename Field::Elt;
  // NJ + 1 so that pluck point NJ decodes to all zeroes
  static constexpr size_t kN = NJ + 1;
  using PolyN = Poly<kN, Field>;
  using InterpolationN = Interpolation<kN, Field>;
  const Logic& l_;
  std::vector<PolyN> plucker_;

  explicit UnaryPlucker(const Logic& l) : l_(l), plucker_(NJ) {
    const Field& F = l_.f_;  // shorthand
    // evaluation points
    PolyN X;
    for (size_t i = 0; i < kN; ++i) {
      X[i] = bit_plucker_point<Field, kN>()(i, F);
    }

    for (size_t j = 0; j < NJ; ++j) {
      PolyN Y;
      for (size_t i = 0; i < kN; ++i) {
        Y[i] = F.of_scalar(i == j);
      }
      plucker_[j] = InterpolationN::monomial_of_lagrange(Y, X, F);
    }
  }

  typename Logic::template bitvec<NJ> pluck(const EltW& e) const {
    typename Logic::template bitvec<NJ> r;
    const Logic& L = l_;  // shorthand
    const Polynomial<Logic> P(L);

    for (size_t j = 0; j < NJ; ++j) {
      EltW v = P.eval(plucker_[j], e);
      L.assert_is_bit(v);
      r[j] = BitW(v, L.f_);
    }

    return r;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_UNARY_PLUCKER_H_
