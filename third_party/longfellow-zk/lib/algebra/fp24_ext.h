// Extensions of Fp24(m) of degree K, represented as P(x) mod (x^K - beta)
// (not upstream; Fp24_6 is the case K = 6). A larger K gives more soundness
// bits to the sumcheck and Ligero challenges: |F| = m^K.
//
// The constructor checks that x^K - beta is irreducible: for each prime r
// dividing K, r divides m - 1 and beta is not an r-th power; and if 4 divides
// K, m = 1 (mod 4). It also checks that a product of two elements cannot
// overflow the 64-bit accumulators.

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP24_EXT_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP24_EXT_H_

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

template <size_t K>
class Fp24Ext {
 public:
  using BaseField = Fp24;
  using Scalar = BaseField::Elt;
  using TypeTag = BaseField::TypeTag;
  using CElt = BaseField::CElt;

  static constexpr size_t kDegree = K;
  static constexpr size_t kBytes = K * BaseField::kBytes;
  static constexpr size_t kBits = K * BaseField::kBits;
  static constexpr size_t kSubFieldBytes = BaseField::kBytes;
  static constexpr size_t kSubFieldBits = BaseField::kBits;
  static constexpr bool kCharacteristicTwo = false;
  static constexpr size_t kNPolyEvaluationPoints =
      BaseField::kNPolyEvaluationPoints;

  struct Elt {
    std::array<Scalar, K> e;
    bool operator==(const Elt& y) const { return e == y.e; }
    bool operator!=(const Elt& y) const { return !operator==(y); }
  };

  Fp24Ext(const BaseField& F, uint32_t beta) : f_(F), beta_(beta) {
    const unsigned __int128 q1 = F.m_ - 1;
    check(static_cast<unsigned __int128>(K) * (1 + beta) * q1 * q1 <
              (static_cast<unsigned __int128>(1) << 64),
          "Fp24Ext accumulators may overflow");
    check(irreducible(), "x^K - beta is not irreducible");
    for (uint64_t i = 0; i < std::size(k_); ++i) k_[i] = of_scalar(i);
    khalf_ = of_scalar(f_.half());
    kmone_ = of_scalar(f_.mone());
  }

  Fp24Ext(const Fp24Ext&) = delete;
  Fp24Ext& operator=(const Fp24Ext&) = delete;

  const BaseField& base_field() const { return f_; }

  void add(Elt& a, const Elt& y) const {
    for (size_t i = 0; i < K; ++i) f_.add(a.e[i], y.e[i]);
  }
  void sub(Elt& a, const Elt& y) const {
    for (size_t i = 0; i < K; ++i) f_.sub(a.e[i], y.e[i]);
  }
  void mul(Elt& a, const Elt& y) const {
    std::array<uint64_t, 2 * K - 1> m{};
    // break the BaseField abstraction
    for (size_t i = 0; i < K; ++i) {
      for (size_t j = 0; j < K; ++j) {
        m[i + j] +=
            static_cast<uint64_t>(a.e[i].n) * static_cast<uint64_t>(y.e[j].n);
      }
    }
    for (size_t i = 0; i + 1 < K; ++i) m[i] += m[i + K] * beta_;
    for (size_t i = 0; i < K; ++i) a.e[i] = f_.reduce(m[i]);
  }
  void mul(Elt& a, const Scalar& y) const {
    for (size_t i = 0; i < K; ++i) f_.mul(a.e[i], y);
  }
  void neg(Elt& x) const {
    for (size_t i = 0; i < K; ++i) f_.neg(x.e[i]);
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

  Elt of_scalar_field(const Scalar& e) const {
    Elt r;
    r.e[0] = e;
    for (size_t i = 1; i < K; ++i) r.e[i] = f_.zero();
    return r;
  }
  Elt of_scalar_field(uint64_t a) const {
    return of_scalar_field(f_.of_scalar(a));
  }
  Elt of_scalar_field(const std::array<uint64_t, K>& a) const {
    Elt e;
    for (size_t i = 0; i < K; ++i) e.e[i] = f_.of_scalar_field(a[i]);
    return e;
  }

  template <size_t N>
  Elt of_string(const char (&s)[N]) const {
    return of_scalar(f_.of_string(s));
  }

  std::optional<Elt> of_bytes_field(const uint8_t ab[/* kBytes */]) const {
    Elt e;
    for (size_t i = 0; i < K; ++i) {
      auto scalar_opt = f_.of_bytes_field(ab + i * BaseField::kBytes);
      if (!scalar_opt.has_value()) return std::nullopt;
      e.e[i] = scalar_opt.value();
    }
    return e;
  }

  Elt sample(
      const std::function<void(size_t n, uint8_t buf[])>& fill_bytes) const {
    Elt e;
    for (size_t i = 0; i < K; ++i) e.e[i] = f_.sample(fill_bytes);
    return e;
  }

  Elt sample_subfield(
      const std::function<void(size_t n, uint8_t buf[])>& fill_bytes) const {
    return of_scalar_field(f_.sample(fill_bytes));
  }

  void to_bytes_field(uint8_t ab[/* kBytes */], const Elt& x) const {
    for (size_t i = 0; i < K; ++i) {
      f_.to_bytes_field(ab + i * BaseField::kBytes, x.e[i]);
    }
  }

  bool in_subfield(const Elt& e) const {
    for (size_t i = 1; i < K; ++i) {
      if (e.e[i] != f_.zero()) return false;
    }
    return true;
  }

  std::optional<Elt> of_bytes_subfield(
      const uint8_t ab[/* kSubFieldBytes */]) const {
    if (auto re = f_.of_bytes_subfield(ab)) return of_scalar(re.value());
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

  BaseField::N from_montgomery(const Elt& x) const {
    check(in_subfield(x), "x not in subfield");
    return f_.from_montgomery(x.e[0]);
  }

 private:
  const BaseField& f_;
  uint32_t beta_;
  Elt k_[3];  // small constants
  Elt khalf_;
  Elt kmone_;

  uint64_t pow_mod(uint64_t b, uint64_t e) const {
    const uint64_t m = f_.m_;
    uint64_t r = 1;
    for (b %= m; e != 0; e >>= 1, b = b * b % m) {
      if (e & 1) r = r * b % m;
    }
    return r;
  }

  bool irreducible() const {
    const uint64_t q1 = f_.m_ - 1;
    if (K % 4 == 0 && f_.m_ % 4 != 1) return false;
    size_t k = K;
    for (size_t r = 2; r <= k; ++r) {
      if (k % r != 0) continue;
      while (k % r == 0) k /= r;
      if (q1 % r != 0 || pow_mod(beta_, q1 / r) == 1) return false;
    }
    return true;
  }

  // Invert via gaussian elimination with partial pivoting: solve
  // A(x) * B(x) = 1 mod (x^K - beta) for the coefficients of B.
  void gaussian_elimination_invert(Elt& x) const {
    std::array<std::array<Scalar, K>, K> A;
    for (size_t i = 0; i < K; ++i) {
      for (size_t j = 0; j < K; ++j) {
        A[i][j] = (i >= j) ? x.e[i - j] : f_.mulf(x.e[i - j + K], beta_);
      }
    }
    x = one();
    for (size_t i = 0; i < K; ++i) {
      size_t r = i;
      while (r < K && A[r][i] == f_.zero()) ++r;
      check(r < K, "element is not invertible");
      std::swap(A[i], A[r]);
      std::swap(x.e[i], x.e[r]);
      const Scalar scal = f_.invertf(A[i][i]);
      for (size_t j = i; j < K; ++j) f_.mul(A[i][j], scal);
      f_.mul(x.e[i], scal);
      for (size_t k = 0; k < K; ++k) {
        if (k == i) continue;
        const Scalar a = A[k][i];
        for (size_t j = i; j < K; ++j) f_.sub(A[k][j], f_.mulf(a, A[i][j]));
        f_.sub(x.e[k], f_.mulf(a, x.e[i]));
      }
    }
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP24_EXT_H_
