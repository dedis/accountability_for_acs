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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_UNARY_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_UNARY_H_

#include <stddef.h>

// Various unary decoders
namespace proofs {
template <class Logic>
class Unary {
 public:
  using BitW = Logic::BitW;
  const Logic& l_;

  explicit Unary(const Logic& l) : l_(l) {}

  // Even with this naive coding, it seems like the EQ circuit
  // contains ~N wires and ~N terms, and the LT circuit contains ~N
  // wires and ~2N terms, so there isn't much room for optimization.

  // A[i] <- (i == j)
  template <size_t W>
  void eq(size_t n, BitW A[/*n*/],
          const typename Logic::template bitvec<W>& j) const {
    for (size_t i = 0; i < n; ++i) {
      A[i] = l_.veq(j, i);
    }
  }

  // A[i] <- (i < j)
  template <size_t W>
  void lt(size_t n, BitW A[/*n*/],
          const typename Logic::template bitvec<W>& j) const {
    for (size_t i = 0; i < n; ++i) {
      A[i] = l_.vlt(i, j);
    }
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_UNARY_H_
