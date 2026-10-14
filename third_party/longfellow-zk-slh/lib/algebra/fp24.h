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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP24_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP24_H_

// 24-bit fields
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>

#include "algebra/fp_generic.h"
#include "algebra/nat.h"
#include "algebra/static_string.h"
#include "algebra/sysdep.h"
#include "util/panic.h"
#include "util/serialization.h"

namespace proofs {
class Fp24 {
 public:
  using N = Nat<1>;
  using TypeTag = PrimeFieldTypeTag;

  static constexpr size_t kU64 = 1;
  static constexpr size_t kBytes = 4;
  static constexpr size_t kSubFieldBytes = 4;
  static constexpr size_t kBits = 32;
  static constexpr size_t kSubFieldBits = kBits;

  static constexpr bool kCharacteristicTwo = false;
  static constexpr size_t kNPolyEvaluationPoints = 6;
  static constexpr bool kSupportsDot = false;

  uint32_t m_;
  struct Elt {
    uint32_t n;
    bool operator==(const Elt& y) const { return n == y.n; }
    bool operator!=(const Elt& y) const { return !operator==(y); }
  };

  explicit Fp24(uint32_t modulus) : m_(modulus), exact_bits_(kBits) {
    check(modulus <= 0xffffff, "modulus exceeds 24 bits");

    // Compute the exact number of bits in the modulus.
    // This value helps with sampling.
    while ((m_ & (1u << (exact_bits_ - 1))) == 0) {
      --exact_bits_;
    }

    for (uint32_t i = 0; i < sizeof(k_) / sizeof(k_[0]); ++i) {
      k_[i] = Elt{i};
    }

    mone_ = negf(k_[1]);
    half_ = Elt{1u + (m_ / 2)};

    for (size_t i = 0; i < kNPolyEvaluationPoints; ++i) {
      poly_evaluation_points_[i] = of_scalar(i);
      if (i == 0) {
        inv_small_scalars_[i] = zero();
      } else {
        inv_small_scalars_[i] = invertf(poly_evaluation_points_[i]);
      }
    }
  }

  Fp24(const Fp24&) = delete;
  Fp24& operator=(const Fp24&) = delete;

  template <size_t N>
  Elt of_string(const char (&s)[N]) const {
    return of_charp(&s[0]);
  }

  Elt of_string(const StaticString& s) const { return of_charp(s.as_pointer); }

  // The of_scalar methods should only be used on trusted inputs known
  // at compile time to be valid field elements. As a result, they return
  // Elt directly instead of std::optional, and panic if the condition is not
  // satisfied. All untrusted input should be handled via the of_bytes method.
  Elt of_scalar(uint64_t a) const { return of_scalar_field(a); }

  Elt of_scalar_field(const std::array<uint64_t, 1>& a) const {
    return of_scalar_field(a[0]);
  }
  Elt of_scalar_field(uint64_t a) const {
    check(static_cast<uint32_t>(a) == a, "scalar too large for uint32_t");
    return of_scalar_field(static_cast<uint32_t>(a));
  }
  Elt of_scalar_field(uint32_t a) const {
    check(a < m_, "of_scalar must be less than m");
    return to_montgomery(a);
  }

  bool fits(uint64_t a) const { return a < m_; }

  // basis for the binary representation of of_scalar(), so that
  // of_scalar(sum_i b[i] 2^i) = sum_i b[i] beta(i)
  Elt beta(size_t i) const {
    check(i < 64, "i < 64");
    return of_scalar(static_cast<uint64_t>(1) << i);
  }

  // a += y
  void add(uint32_t& a, uint32_t y) const { a = addcmovc_32(a - m_, y, a + y); }
  void add(Elt& a, Elt y) const { add(a.n, y.n); }

  // a -= y
  //
  void sub(uint32_t& a, uint32_t y) const { a = sub_sysdep_32(a, y, m_); }
  void sub(Elt& a, Elt y) const { sub(a.n, y.n); }

  // x = -x
  void neg(Elt& x) const {
    Elt y{0};
    sub(y, x);
    x = y;
  }

  void mul(uint32_t& x, const Elt& y) const {
    x = (static_cast<uint64_t>(x) * static_cast<uint64_t>(y.n)) % m_;
  }
  void mul(Elt& a, Elt y) const { mul(a.n, y); }

  // x = 1/x
  void invert(Elt& x) const { x = invertf(x); }

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
  Elt mulf(Elt a, const uint32_t y) const {
    mul(a, Elt{y});
    return a;
  }
  Elt negf(Elt a) const {
    neg(a);
    return a;
  }

  // This is the binary extended gcd algorithm, modified
  // to return the inverse of x.
  Elt invertf(Elt x) const {
    uint32_t a = x.n;
    uint32_t b = m_;
    Elt u = one();
    Elt v = zero();
    while (a != 0) {
      if ((a & 0x1u) == 0) {
        a >>= 1;
        byhalf(u);
      } else {
        if (a < b) {  // swap to maintain invariant
          std::swap(a, b);
          std::swap(u, v);
        }
        a = (a - b) >> 1;
        sub(u, v);
        byhalf(u);
      }
    }
    return v;
  }

  Elt zero() const { return Elt{0}; }
  const Elt& one() const { return k_[1]; }
  const Elt& two() const { return k_[2]; }
  const Elt& half() const { return half_; }
  const Elt& mone() const { return mone_; }

  Elt poly_evaluation_point(size_t i) const {
    check(i < kNPolyEvaluationPoints, "i < kNPolyEvaluationPoints");
    return poly_evaluation_points_[i];
  }

  // return (X[k] - X[k - i])^{-1}, were X[i] is the
  // i-th poly evalaluation point.
  Elt newton_denominator(size_t k, size_t i) const {
    check(k < kNPolyEvaluationPoints, "k < kNPolyEvaluationPoints");
    check(i <= k, "i <= k");
    check(k != (k - i), "k != (k - i)");
    return inv_small_scalars_[/* k - (k - i) = */ i];
  }

  // Type for counters.  For prime fields counters and field
  // elements have the same representation, so all conversions
  // are trivial.
  struct CElt {
    Elt e;
  };
  CElt as_counter(uint64_t a) const { return CElt{of_scalar_field(a)}; }

  // Convert a counter into *some* field element such that the counter is
  // zero (as a counter) iff the field element is zero.
  Elt znz_indicator(const CElt& celt) const { return celt.e; }

  // Reference implementation, unused.
  N from_montgomery_reference(Elt x) const { return from_montgomery(x); }

  N from_montgomery(Elt x) const { return N{x.n}; }

  Elt to_montgomery(uint64_t xn) const {
    return Elt{static_cast<uint32_t>(xn)};
  }

  // Added to pass tests which verify the from_, to_ inverse relationship.
  Elt to_montgomery(const N& xn) const {
    std::array<uint64_t, 1> u = xn.u64();
    return to_montgomery(u[0]);
  }

  bool in_subfield(Elt e) const { return true; }

  std::optional<Elt> of_bytes_field(const uint8_t ab[/* kBytes */]) const {
    uint32_t an = u32_of_le(ab);
    if (fits(an)) {
      return to_montgomery(an);
    } else {
      return std::nullopt;
    }
  }

  void to_bytes_field(uint8_t ab[/* kBytes */], const Elt& x) const {
    u32_to_le(ab, x.n);
  }

  std::optional<Elt> of_bytes_subfield(const uint8_t ab[/* kBytes */]) const {
    return of_bytes_field(ab);
  }

  void to_bytes_subfield(uint8_t ab[/* kBytes */], const Elt& x) const {
    to_bytes_field(ab, x);
  }

  Elt sample(
      const std::function<void(size_t n, uint8_t buf[])>& fill_bytes) const {
    const size_t total_l = (exact_bits_ + 7) / 8;
    const uint32_t mask = (~static_cast<uint32_t>(0)) >> (32 - exact_bits_);
    uint8_t buf[kBytes] = {0};
    for (;;) {
      fill_bytes(total_l, buf);
      uint32_t an = u32_of_le(buf);
      an &= mask;
      if (an < m_) {
        return to_montgomery(an);
      }
    }
  }

  Elt sample_subfield(
      const std::function<void(size_t n, uint8_t buf[])>& fill_bytes) const {
    return sample(fill_bytes);
  }

  // dot product is not supported
  struct NatScaledForDot {};

  NatScaledForDot prescale_for_dot(Elt e) const {
    check(false, "prescale_for_dot() not implemented");
    return NatScaledForDot{};
  }

  template <size_t WX>
  Elt reduce(const Nat<WX>& xn) const {
    // Need one-limb reduction for crt.h, but other
    // cases are not needed.
    if (WX == 1) {
      std::array<uint64_t, WX> u = xn.u64();
      return reduce(u[0]);
    } else {
      check(false, "reduce() not implemented");
      return zero();
    }
  }
  Elt dot(size_t n, const Nat<1> a[/*n*/],
          const NatScaledForDot b[/*n*/]) const {
    check(false, "dot() not implemented");
    return zero();
  }
  Elt reduce(uint64_t x) const { return Elt{static_cast<uint32_t>(x % m_)}; }

 private:
  // This method should only be used on static strings known at
  // compile time to be valid field elements.  We make it
  // private to prevent misuse.
  Elt of_charp(const char* s) const {
    Elt a(k_[0]);
    Elt base = of_scalar(10);
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
      s += 2;
      base = of_scalar(16);
    }

    for (; *s; s++) {
      Elt d = of_scalar(digit(*s));
      mul(a, base);
      add(a, d);
    }
    return a;
  }

  void byhalf(Elt& a) const {
    uint32_t b = a.n & 1;
    a.n >>= 1;
    if (b != 0) {
      add(a, half_);
    }
  }

  size_t exact_bits_;
  Elt k_[3];  // small constants
  Elt half_;  // 1/2
  Elt mone_;  // minus one
  Elt poly_evaluation_points_[kNPolyEvaluationPoints];
  Elt inv_small_scalars_[kNPolyEvaluationPoints];
};
}  // namespace proofs
#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP24_H_
