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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_REED_SOLOMON_EXTENSION_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_REED_SOLOMON_EXTENSION_H_

#include <stddef.h>

#include <memory>
#include <utility>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/fp24.h"
#include "algebra/fp24_6.h"
#include "algebra/reed_solomon.h"

namespace proofs {

/*
The ReedSolomonExtension6 class implements a form of RS encoding when the
evaluation points belong to a base field, but the message is defined over
a degree 6 extension field.  In this case, the RS encoding can be viewed as the
encoding each of the components of the message separately using the base
field, and then combining the results.

This implementation only works for Fp24_6.
*/
class ReedSolomonExtension6 {
  using BaseField = Fp24;
  using Elt = typename BaseField::Elt;
  using ExtElt = typename Fp24_6::Elt;

  CrtConvolutionFactory<CRT<1, Fp24>, Fp24> crt_convolution_factory_;
  using RSF =
      ReedSolomonFactory<Fp24, CrtConvolutionFactory<CRT<1, Fp24>, Fp24>>;
  RSF rsf_;

 public:
  // n is the number of points input
  // m is the total number of points output (including the initial n points)
  ReedSolomonExtension6(size_t n, size_t m, const BaseField& f)
      : crt_convolution_factory_(f),
        rsf_(crt_convolution_factory_, f),
        rs_(rsf_.make(n, m)),
        degree_bound_(n - 1),
        m_(m) {}

  // Given the values of a polynomial of degree at most n at 0, 1, 2, ..., n-1,
  // this computes the values at n, n+1, n+2, ..., m-1.
  // (n points go in, m points come out)
  void interpolate(ExtElt y[/*m*/]) const {
    // shorthands
    size_t n = degree_bound_ + 1;  // number of points input

    // Compute the RS encoding of each of the components of the message
    // separately.
    std::vector<Elt> T(m_);
    for (size_t d = 0; d < 6; ++d) {
      // copy inputs to T
      for (size_t i = 0; i < n; ++i) {
        T[i] = y[i].e[d];
      }
      rs_->interpolate(&T[0]);
      // copy output to y
      for (size_t i = n; i < m_; ++i) {
        y[i].e[d] = T[i];
      }
    }
  }

 private:
  decltype(std::declval<const RSF&>().make(1, 1)) rs_;

  const size_t degree_bound_;  // degree bound, i.e., n - 1
  // total number of points output (points in + new points out)
  const size_t m_;
};

class ReedSolomonExtensionFactory {
  using BaseField = Fp24;

 public:
  explicit ReedSolomonExtensionFactory(const BaseField& f) : base_field_(f) {}

  std::unique_ptr<ReedSolomonExtension6> make(size_t n, size_t m) const {
    return std::make_unique<ReedSolomonExtension6>(n, m, base_field_);
  }

 private:
  const BaseField& base_field_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_REED_SOLOMON_EXTENSION_H_
