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

#ifndef PRIVACY_PROOFS_ZK_LIB_ARRAYS_SPARSE_H_
#define PRIVACY_PROOFS_ZK_LIB_ARRAYS_SPARSE_H_

#include <stddef.h>

#include <algorithm>
#include <memory>
#include <vector>

#include "algebra/compare.h"
#include "algebra/poly.h"
#include "arrays/affine.h"
#include "util/panic.h"

namespace proofs {
// ------------------------------------------------------------
// Sparse representation of multi-affine functions.
//
// This class is mainly used as a reference implementation
// for testing, and it exposes a similar interface as dense<Field>.
// Sumcheck has its own specialized "quad" implementation.
//
template <class Field>
class Sparse {
  using Elt = typename Field::Elt;
  using T2 = Poly<2, Field>;

 public:
  // A corner on the sparse hypercube, represented as triple of size_t
  // and a value.  The 3D representation is kind of a guess of how
  // many bits we'll ever need.  Under the theory that "size_t" has
  // enough bits to index a dense array that fills the address space,
  // and that the program should support |points| gates, and each gate
  // has three terminals, then a triple ought to be both necessary and
  // sufficient.
  struct corner {
    size_t p0, p1, p2;
    Elt v;

    bool eqndx(const corner& y) const {
      return (p2 == y.p2 && p1 == y.p1 && p0 == y.p0);
    }
    bool operator==(const corner& y) const { return eqndx(y) && v == y.v; }
    bool operator!=(const corner& y) const { return !operator==(y); }

    static bool compare(const corner& x, const corner& y, const Field& F) {
      if (x.p2 < y.p2) return true;
      if (x.p2 > y.p2) return false;
      if (x.p1 < y.p1) return true;
      if (x.p1 > y.p1) return false;
      if (x.p0 < y.p0) return true;
      if (x.p0 > y.p0) return false;
      return elt_less_than(x.v, y.v, F);
    }
  };

  // the index of a point in a sparse array
  using index_t = size_t;

  index_t n_;
  std::vector<corner> c_;

  explicit Sparse(index_t n) : n_(n), c_(n) {}

  // no copies, but see clone() below
  Sparse(const Sparse& y) = delete;
  Sparse(const Sparse&& y) = delete;
  Sparse operator=(const Sparse& y) = delete;

  // Nobody should need to clone a sparse array except tests.
  // Reflect this fact in the name.
  std::unique_ptr<Sparse> clone_testing_only() const {
    auto s = std::make_unique<Sparse>(n_);
    for (index_t i = 0; i < n_; ++i) {
      s->c_[i] = c_[i];
    }
    return s;
  }

  T2 t2_at_corners(index_t* newi, index_t i, const Field& F) const {
    // If c_[i] and c_[i+1] have the same (P2, P1), and they differ
    // by the least-significant bit in P0:
    if (i + 1 < n_ &&                              //
        c_[i].p2 == c_[i + 1].p2 &&                //
        c_[i].p1 == c_[i + 1].p1 &&                //
        (c_[i].p0 >> 1) == (c_[i + 1].p0 >> 1) &&  //
        c_[i + 1].p0 == c_[i].p0 + 1) {
      // we have two corners.
      *newi = i + 2;
      return T2{c_[i].v, c_[i + 1].v};
    } else {
      // we have one corner and the other one is zero.
      *newi = i + 1;
      if ((c_[i].p0 & 1) == 0) {
        return T2{c_[i].v, F.zero()};
      } else {
        return T2{F.zero(), c_[i].v};
      }
    }
  }

  // For a given random number r, the binding operation computes
  //   v[p2, p1, p0] = (1 - r) * v[p2, p1, 2 * p0] + r * v[p2, p1, 2 * p0 + 1]
  // Note that either the odd or the even element or both may not be actually
  // present in the sparse array.
  void bind(const Elt& r, const Field& F) {
    index_t rd = 0, wr = 0;
    while (rd < n_) {
      index_t newrd;
      T2 f = t2_at_corners(&newrd, rd, F);
      c_[wr] = corner{.p0 = c_[rd].p0 >> 1,
                      .p1 = c_[rd].p1,
                      .p2 = c_[rd].p2,
                      .v = affine_interpolation(r, f.t_[0], f.t_[1], F)};
      wr++;
      rd = newrd;
    }

    // shrink the array
    n_ = wr;
  }

  void bind_all(size_t logv, const Elt r[/*logv*/], const Field& F) {
    for (size_t v = 0; v < logv; ++v) {
      bind(r[v], F);
    }
  }

  void reshape() {
    // this function works only if c_[i].p0 == 0 for all i, but
    // rather than checking them one at the time, keep a giant
    // bitwise OR and check at the end
    size_t lost_bits = 0;
    for (index_t i = 0; i < n_; ++i) {
      lost_bits |= c_[i].p0;
      c_[i] = corner{.p0 = c_[i].p1, .p1 = c_[i].p2, .p2 = 0, .v = c_[i].v};
    }
    check(lost_bits == 0, "lost_bits == 0");
  }

  // This method can only be called after full binding; the caller
  // is responsible for ensuring that pre-condition.
  Elt scalar() {
    check(n_ == 1, "n_ == 1");
    check(c_[0].p0 == 0, "c_[0].p0_ == 0");
    check(c_[0].p1 == 0, "c_[0].p1_ == 0");
    check(c_[0].p2 == 0, "c_[0].p2_ == 0");
    return c_[0].v;
  }

  void canonicalize(const Field& F) {
    std::sort(c_.begin(), c_.begin() + n_,
              [&F](const corner& x, const corner& y) {
                return corner::compare(x, y, F);
              });
    return coalesce(F);
  }

 private:
  void coalesce(const Field& F) {
    // Coalesce duplicates.
    // The (rd,wr)=(0,0) iteration executes the else{} branch and
    // continues with (1,1), so we start at (1,1) and avoid the
    // special case for wr-1 at wr=0.
    index_t wr = 1;
    for (index_t rd = 1; rd < n_; ++rd) {
      if (c_[rd].eqndx(c_[wr - 1])) {
        F.add(c_[wr - 1].v, c_[rd].v);
      } else {
        c_[wr] = c_[rd];
        wr++;
      }
    }
    n_ = wr;
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ARRAYS_SPARSE_H_
