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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP24_6_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP24_6_H_

#include <stddef.h>

#include <array>
#include <cstdint>
#include <functional>
#include <iterator>
#include <optional>
#include <utility>

#include "algebra/fp24.h"
#include "util/panic.h"

namespace proofs {
// Sextic extensions of Fp24(m), represented as P(x) mod (x^6 - beta),
// where (x^6 - beta) is assumed to be irreducible.
class Fp24_6 {
 public:
  using BaseField = Fp24;
  using Scalar = BaseField::Elt;
  using TypeTag = BaseField::TypeTag;
  using CElt = BaseField::CElt;

  // size of the serialization into bytes
  static constexpr size_t kBytes = 6 * BaseField::kBytes;
  static constexpr size_t kBits = 6 * BaseField::kBits;
  static constexpr size_t kSubFieldBytes = BaseField::kBytes;
  static constexpr size_t kSubFieldBits = BaseField::kBits;
  static constexpr bool kCharacteristicTwo = false;
  static constexpr size_t kNPolyEvaluationPoints =
      BaseField::kNPolyEvaluationPoints;

  struct Elt {
    std::array<Scalar, 6> e;
    bool operator==(const Elt& y) const { return e == y.e; }
    bool operator!=(const Elt& y) const { return !operator==(y); }
  };

  explicit Fp24_6(const BaseField& F, const uint32_t beta)
      : f_(F), beta_(beta) {
    // We need to compute length-6 sums of a[i] * b[j] * beta.
    // A and B are 24 bit.  Beta is 12 bits.  Total is 63 bits.
    check(beta <= 0xfff, "beta exceeds 12 bits");

    for (uint64_t i = 0; i < std::size(k_); ++i) {
      k_[i] = of_scalar(i);
    }
    khalf_ = of_scalar(f_.half());
    kmone_ = of_scalar(f_.mone());
  }

  // Fp24_6 is not copyable or assignable because it holds a reference to a
  // Field and precomputes constants based on that field.
  Fp24_6(const Fp24_6&) = delete;
  Fp24_6& operator=(const Fp24_6&) = delete;

  const BaseField& base_field() const { return f_; }

  void add(Elt& a, const Elt& y) const {
    for (size_t i = 0; i < 6; ++i) {
      f_.add(a.e[i], y.e[i]);
    }
  }
  void sub(Elt& a, const Elt& y) const {
    for (size_t i = 0; i < 6; ++i) {
      f_.sub(a.e[i], y.e[i]);
    }
  }
  void mul(Elt& a, const Elt& y) const {
    std::array<uint64_t, 11> m{};
    // break the BaseField abstraction
    for (size_t i = 0; i < 6; ++i) {
      for (size_t j = 0; j < 6; ++j) {
        m[i + j] +=
            static_cast<uint64_t>(a.e[i].n) * static_cast<uint64_t>(y.e[j].n);
      }
    }
    for (size_t i = 0; i < 5; ++i) {
      m[i] += m[i + 6] * beta_;
    }
    for (size_t i = 0; i < 6; ++i) {
      a.e[i] = f_.reduce(m[i]);
    }
  }
  void mul(Elt& a, const Scalar& y) const {
    for (size_t i = 0; i < 6; ++i) {
      f_.mul(a.e[i], y);
    }
  }
  void neg(Elt& x) const {
    for (size_t i = 0; i < 6; ++i) {
      f_.neg(x.e[i]);
    }
  }
  void invert(Elt& x) const {
    if (in_subfield(x)) {
      f_.invert(x.e[0]);
    } else {
      gaussian_elimination_invert(x);
    }
  }

  // functional interface
  Elt addf(Elt a, const Elt& y) const {
    add(a, y);
    return a;
  }
  Elt subf(Elt a, const Elt& y) const {
    sub(a, y);
    return a;
  }
  Elt mulf(Elt a, const Elt& y) const {
    mul(a, y);
    return a;
  }
  Elt mulf(Elt a, const Scalar& y) const {
    mul(a, y);
    return a;
  }
  Elt negf(Elt a) const {
    neg(a);
    return a;
  }
  Elt invertf(Elt a) const {
    invert(a);
    return a;
  }

  bool fits(uint64_t a) const { return f_.fits(a); }

  Elt of_scalar(uint64_t a) const { return of_scalar_field(a); }
  Elt of_scalar(const Scalar& e) const { return of_scalar_field(e); }

  Elt of_scalar_field(const Scalar& e) const { return Elt{e}; }
  Elt of_scalar_field(uint64_t a) const { return Elt{f_.of_scalar(a)}; }
  Elt of_scalar_field(const std::array<uint64_t, 6>& a) const {
    Elt e;
    for (size_t i = 0; i < 6; ++i) {
      e.e[i] = f_.of_scalar_field(a[i]);
    }
    return e;
  }

  template <size_t N>
  Elt of_string(const char (&s)[N]) const {
    return of_scalar(f_.of_string(s));
  }

  std::optional<Elt> of_bytes_field(const uint8_t ab[/* kBytes */]) const {
    Elt e;
    for (size_t i = 0; i < 6; ++i) {
      auto scalar_opt = f_.of_bytes_field(ab + i * BaseField::kBytes);
      if (!scalar_opt.has_value()) {
        return std::nullopt;
      }
      e.e[i] = scalar_opt.value();
    }
    return e;
  }

  Elt sample(
      const std::function<void(size_t n, uint8_t buf[])>& fill_bytes) const {
    Elt e;
    for (size_t i = 0; i < 6; ++i) {
      e.e[i] = f_.sample(fill_bytes);
    }
    return e;
  }

  Elt sample_subfield(
      const std::function<void(size_t n, uint8_t buf[])>& fill_bytes) const {
    auto re = f_.sample(fill_bytes);
    return of_scalar_field(re);
  }

  void to_bytes_field(uint8_t ab[/* kBytes */], const Elt& x) const {
    for (size_t i = 0; i < 6; ++i) {
      f_.to_bytes_field(ab + i * BaseField::kBytes, x.e[i]);
    }
  }

  bool in_subfield(const Elt& e) const {
    for (size_t i = 1; i < 6; ++i) {
      if (e.e[i] != f_.zero()) return false;
    }
    return true;
  }

  std::optional<Elt> of_bytes_subfield(
      const uint8_t ab[/* kSubFieldBytes */]) const {
    if (auto re = f_.of_bytes_subfield(ab)) {
      return of_scalar(re.value());
    }
    return std::nullopt;
  }

  void to_bytes_subfield(uint8_t ab[/* kSubFieldBytes */], const Elt& x) const {
    check(in_subfield(x), "x not in subfield");
    f_.to_bytes_subfield(ab, x.e[0]);
  }

  const Elt& zero() const { return k_[0]; }
  const Elt& one() const { return k_[1]; }
  const Elt& two() const { return k_[2]; }
  const Elt& half() const { return khalf_; }
  const Elt& mone() const { return kmone_; }

  Elt beta(size_t i) const { return of_scalar(f_.beta(i)); }

  Elt poly_evaluation_point(size_t i) const {
    return of_scalar(f_.poly_evaluation_point(i));
  }
  Elt newton_denominator(size_t k, size_t i) const {
    return of_scalar(f_.newton_denominator(k, i));
  }

  // Optimized implementation of from_montgomery_reference(), exploiting
  // the fact that the multiplicand is Elt{N(1)}.
  BaseField::N from_montgomery(const Elt& x) const {
    for (size_t i = 1; i < 6; ++i) {
      check(x.e[i] == f_.zero(), "x not in subfield");
    }
    return f_.from_montgomery(x.e[0]);
  }

 private:
  const BaseField& f_;
  uint32_t beta_;
  Elt k_[3];  // small constants
  Elt khalf_;
  Elt kmone_;

  // Invert via gaussian elimination with partial pivoting
  //
  // Viewing the element X to be inverted as a polynomial
  // A(x), we want to find B(x) such that A(x) * B(x) = 1
  // mod (x^6 - beta).  View this as a system of linear
  // equations in the coefficients of B.
  void gaussian_elimination_invert(Elt& x) const {
    constexpr size_t n = 6;
    std::array<std::array<Scalar, n>, n> A;

    // Set up the beta-circulant matrix representing the Elt
    // to be inverted
    for (size_t i = 0; i < n; ++i) {
      for (size_t j = 0; j < n; ++j) {
        A[i][j] = (i >= j) ? x.e[i - j] : f_.mulf(x.e[i - j + n], beta_);
      }
    }

    // initialize the right-hand side B, stored in-place as X
    x = one();

    // gaussian elimination
    for (size_t i = 0; i < n; ++i) {
      for (size_t r = i; r < n; ++r) {
        if (A[r][i] != f_.zero()) {
          if (i != r) {
            std::swap(A[i], A[r]);
            std::swap(x.e[i], x.e[r]);
          }
          goto have_pivot;
        }
      }
      check(false, "element is not invertible");

    have_pivot:
      Scalar scal = f_.invertf(A[i][i]);
      for (size_t j = i; j < n; ++j) {
        f_.mul(A[i][j], scal);
      }
      f_.mul(x.e[i], scal);

      // eliminate all other rows k
      for (size_t k = 0; k < n; ++k) {
        if (k != i) {
          Scalar a = A[k][i];
          for (size_t j = i; j < n; ++j) {
            f_.sub(A[k][j], f_.mulf(a, A[i][j]));
          }
          f_.sub(x.e[k], f_.mulf(a, x.e[i]));
        }
      }
    }
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP24_6_H_
