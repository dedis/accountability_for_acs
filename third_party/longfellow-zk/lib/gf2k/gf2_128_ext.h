// Extensions of GF(2^128) of degree D = 2 or 3 (not upstream): GF(2^256)
// and GF(2^384), for proofs that need more than the about 113 bits of
// soundness that a 128-bit field allows.
//
// An element is c[0] + c[1] y + ... + c[D-1] y^(D-1) with c[i] in GF(2^128)
// and y a root of an irreducible polynomial over GF(2^128):
//
//   D = 2: y^2 = y + alpha, with Tr(alpha) = 1 (Artin-Schreier);
//   D = 3: y^3 = alpha, with alpha not a cube.
//
// ALPHA is the first of x, x^2, ..., x^127 that satisfies the condition
// (for D = 2, x^121: Tr(x^k) = 0 for k < 121 by Newton's identities on the
// modulus x^128 + x^7 + x^2 + x + 1). The subfield is GF(2^16) of the
// base field, so the Reed-Solomon evaluation points, the counters and the
// sumcheck evaluation points are those of GF2_128.

#ifndef PRIVACY_PROOFS_ZK_LIB_GF2K_GF2_128_EXT_H_
#define PRIVACY_PROOFS_ZK_LIB_GF2K_GF2_128_EXT_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>

#include "gf2k/gf2_128.h"
#include "util/panic.h"

namespace proofs {

template <size_t D>
class GF2_128Ext {
  static_assert(D == 2 || D == 3, "degree 2 or 3");

 public:
  using BaseField = GF2_128<>;
  using Scalar = BaseField::Elt;
  using TypeTag = BinaryFieldTypeTag;

  static constexpr size_t kDegree = D;
  static constexpr size_t kBits = D * BaseField::kBits;
  static constexpr size_t kBytes = D * BaseField::kBytes;
  static constexpr size_t kSubFieldLogBits = BaseField::kSubFieldLogBits;
  static constexpr size_t kSubFieldBits = BaseField::kSubFieldBits;
  static constexpr size_t kSubFieldBytes = BaseField::kSubFieldBytes;
  static constexpr size_t kNPolyEvaluationPoints =
      BaseField::kNPolyEvaluationPoints;
  static constexpr bool kCharacteristicTwo = true;

  struct Elt {
    std::array<Scalar, D> e;
    bool operator==(const Elt& y) const { return e == y.e; }
    bool operator!=(const Elt& y) const { return !operator==(y); }
  };

  struct CElt {
    Elt e;
    bool operator==(const CElt& y) const { return e == y.e; }
    bool operator!=(const CElt& y) const { return !operator==(y); }
  };

  GF2_128Ext() {
    for (size_t k = 1;; ++k) {
      check(k < BaseField::kBits, "no modulus found");
      std::array<uint64_t, 2> xk = {0, 0};
      xk[k / 64] = uint64_t(1) << (k % 64);
      alpha_ = f_.of_scalar_field(xk);
      kalpha_ = k;
      if (D == 2 ? trace(alpha_) == f_.one() : !is_cube(alpha_)) break;
    }
  }

  GF2_128Ext(const GF2_128Ext&) = delete;
  GF2_128Ext& operator=(const GF2_128Ext&) = delete;

  const BaseField& base_field() const { return f_; }
  Scalar alpha() const { return alpha_; }

  // Field operations.
  Elt addf(const Elt& x, const Elt& y) const {
    Elt r;
    for (size_t i = 0; i < D; ++i) r.e[i] = f_.addf(x.e[i], y.e[i]);
    return r;
  }
  Elt subf(const Elt& x, const Elt& y) const { return addf(x, y); }
  Elt negf(const Elt& x) const { return x; }
  // The products of base coordinates are summed before their reduction
  // (BaseField::Wide, combine()), and alpha = x^k multiplies by a shift
  // (not upstream): 18 instead of 24 carry-less multiplications for D = 2,
  // 34 instead of 48 for D = 3. The same element.
  Elt mulf(const Elt& x, const Elt& y) const {
    Acc a;
    a.m[0] = BaseField::mul_wide(x.e[0], y.e[0]);
    a.m[1] = BaseField::mul_wide(x.e[1], y.e[1]);
    if constexpr (D == 2) {
      a.m[2] = BaseField::mul_wide(f_.addf(x.e[0], x.e[1]),
                                   f_.addf(y.e[0], y.e[1]));
    } else {
      a.m[2] = BaseField::mul_wide(x.e[2], y.e[2]);
      a.m[3] = BaseField::mul_wide(f_.addf(x.e[0], x.e[1]),
                                   f_.addf(y.e[0], y.e[1]));
      a.m[4] = BaseField::mul_wide(f_.addf(x.e[0], x.e[2]),
                                   f_.addf(y.e[0], y.e[2]));
      a.m[5] = BaseField::mul_wide(f_.addf(x.e[1], x.e[2]),
                                   f_.addf(y.e[1], y.e[2]));
    }
    return combine(a.m);
  }
  // Sums of products before their reduction (not upstream): the Karatsuba
  // products of mulf() are summed unreduced (XOR), and reduce() combines
  // and reduces the sums once. The same element as the sum of mulf().
  struct Acc {
    typename BaseField::Wide m[D == 2 ? 3 : 6];
  };
  Acc acc() const {
    Acc a;
    for (auto& w : a.m) w = BaseField::zero_wide();
    return a;
  }
  void mac(Acc& a, const Elt& x, const Elt& y) const {
    auto add = [&](size_t k, const Scalar& u, const Scalar& v) {
      a.m[k] = BaseField::add_wide(a.m[k], BaseField::mul_wide(u, v));
    };
    add(0, x.e[0], y.e[0]);
    add(1, x.e[1], y.e[1]);
    if constexpr (D == 2) {
      add(2, f_.addf(x.e[0], x.e[1]), f_.addf(y.e[0], y.e[1]));
    } else {
      add(2, x.e[2], y.e[2]);
      add(3, f_.addf(x.e[0], x.e[1]), f_.addf(y.e[0], y.e[1]));
      add(4, f_.addf(x.e[0], x.e[2]), f_.addf(y.e[0], y.e[2]));
      add(5, f_.addf(x.e[1], x.e[2]), f_.addf(y.e[1], y.e[2]));
    }
  }
  Elt reduce(const Acc& a) const { return combine(a.m); }

  Elt invertf(const Elt& x) const {
    if constexpr (D == 2) {
      // (a + b y)(a + b + b y) = a^2 + a b + alpha b^2, in the base field.
      const Scalar& a = x.e[0];
      const Scalar& b = x.e[1];
      const Scalar norm = f_.addf(f_.addf(f_.mulf(a, a), f_.mulf(a, b)),
                                  f_.mulf(alpha_, f_.mulf(b, b)));
      check(norm != f_.zero(), "element is not invertible");
      const Scalar inv = f_.invertf(norm);
      return Elt{{f_.mulf(f_.addf(a, b), inv), f_.mulf(b, inv)}};
    } else {
      return gaussian_elimination_invert(x);
    }
  }

  void add(Elt& a, const Elt& y) const { a = addf(a, y); }
  void sub(Elt& a, const Elt& y) const { a = subf(a, y); }
  void mul(Elt& a, const Elt& y) const { a = mulf(a, y); }
  void neg(Elt& a) const { /* noop */ }
  void invert(Elt& a) const { a = invertf(a); }

  // Elements of the base field and of its subfield.
  Elt of_base(const Scalar& s) const {
    Elt r;
    r.e[0] = s;
    for (size_t i = 1; i < D; ++i) r.e[i] = f_.zero();
    return r;
  }
  Elt of_scalar(uint64_t u) const { return of_base(f_.of_scalar(u)); }
  Elt of_scalar_field(uint64_t n) const {
    return of_base(f_.of_scalar_field(n));
  }

  Elt zero() const { return of_base(f_.zero()); }
  Elt one() const { return of_base(f_.one()); }
  Elt mone() const { return one(); }
  Elt x() const { return of_base(f_.x()); }
  Elt invx() const { return of_base(f_.invx()); }
  Elt g() const { return of_base(f_.g()); }
  Elt invg() const { return of_base(f_.invg()); }
  Elt beta(size_t i) const { return of_base(f_.beta(i)); }
  Elt poly_evaluation_point(size_t i) const {
    return of_base(f_.poly_evaluation_point(i));
  }
  Elt newton_denominator(size_t k, size_t i) const {
    return of_base(f_.newton_denominator(k, i));
  }

  CElt as_counter(uint64_t a) const {
    return CElt{of_base(f_.as_counter(a).e)};
  }
  Elt counter_beta(size_t i) const { return of_base(f_.counter_beta(i)); }
  Elt znz_indicator(const CElt& celt) const { return subf(celt.e, one()); }

  // Serialization: the D base coordinates, each in the GF2_128 format.
  std::optional<Elt> of_bytes_field(const uint8_t ab[/* kBytes */]) const {
    Elt r;
    for (size_t i = 0; i < D; ++i) {
      auto c = f_.of_bytes_field(ab + i * BaseField::kBytes);
      if (!c.has_value()) return std::nullopt;
      r.e[i] = c.value();
    }
    return r;
  }
  void to_bytes_field(uint8_t ab[/* kBytes */], const Elt& x) const {
    for (size_t i = 0; i < D; ++i) {
      f_.to_bytes_field(ab + i * BaseField::kBytes, x.e[i]);
    }
  }

  bool in_subfield(const Elt& x) const {
    for (size_t i = 1; i < D; ++i) {
      if (x.e[i] != f_.zero()) return false;
    }
    return f_.in_subfield(x.e[0]);
  }
  std::optional<Elt> of_bytes_subfield(
      const uint8_t ab[/* kSubFieldBytes */]) const {
    auto s = f_.of_bytes_subfield(ab);
    if (!s.has_value()) return std::nullopt;
    return of_base(s.value());
  }
  // The base field checks that x.e[0] lies in its subfield.
  void to_bytes_subfield(uint8_t ab[/* kSubFieldBytes */], const Elt& x) const {
    for (size_t i = 1; i < D; ++i) check(x.e[i] == f_.zero(), "x not in subfield");
    f_.to_bytes_subfield(ab, x.e[0]);
  }

  // Every byte string is an element, so sampling is uniform.
  Elt sample(
      const std::function<void(size_t n, uint8_t buf[])>& fill_bytes) const {
    Elt r;
    for (size_t i = 0; i < D; ++i) r.e[i] = f_.sample(fill_bytes);
    return r;
  }
  Elt sample_subfield(
      const std::function<void(size_t n, uint8_t buf[])>& fill_bytes) const {
    return of_base(f_.sample_subfield(fill_bytes));
  }

 private:
  // The element from the unreduced Karatsuba products M (mulf).
  Elt combine(const typename BaseField::Wide* m) const {
    using W = typename BaseField::Wide;
    auto sum = [](const W& a, const W& b) { return BaseField::add_wide(a, b); };
    auto red = [](const W& a) { return BaseField::reduce_wide(a); };
    // alpha * A, A reduced.
    auto alpha = [&](const Scalar& a) {
      return BaseField::shift_wide(a, kalpha_);
    };
    Elt r;
    if constexpr (D == 2) {
      // m = x0 y0, x1 y1, (x0 + x1)(y0 + y1); y^2 = y + alpha.
      r.e[0] = red(sum(m[0], alpha(red(m[1]))));
      r.e[1] = red(sum(m[2], m[0]));
    } else {
      // m = x0 y0, x1 y1, x2 y2, (x0 + x1)(y0 + y1), (x0 + x2)(y0 + y2),
      // (x1 + x2)(y1 + y2); y^3 = alpha:
      //   c1 = (x0 + x1)(y0 + y1) - m0 - m1
      //   c2 = (x0 + x2)(y0 + y2) - m0 - m2 + m1
      //   c3 = (x1 + x2)(y1 + y2) - m1 - m2
      const Scalar c3 = red(sum(m[5], sum(m[1], m[2])));
      const Scalar c4 = red(m[2]);
      r.e[0] = red(sum(m[0], alpha(c3)));
      r.e[1] = red(sum(sum(m[3], sum(m[0], m[1])), alpha(c4)));
      r.e[2] = red(sum(m[4], sum(m[0], sum(m[2], m[1]))));
    }
    return r;
  }

  // Tr(a) = a + a^2 + a^4 + ... + a^(2^127), in GF(2).
  Scalar trace(Scalar a) const {
    Scalar t = f_.zero();
    for (size_t i = 0; i < BaseField::kBits; ++i) {
      f_.add(t, a);
      f_.mul(a, a);
    }
    return t;
  }

  // A is a cube iff A^((2^128 - 1) / 3) = 1; the exponent is 0x5555...55.
  bool is_cube(const Scalar& a) const {
    Scalar r = f_.one();
    for (size_t i = BaseField::kBits; i-- > 0;) {
      f_.mul(r, r);
      if (i % 2 == 0) f_.mul(r, a);
    }
    return r == f_.one();
  }

  // Solves X * Z = 1 for the coordinates of Z.
  Elt gaussian_elimination_invert(const Elt& x) const {
    // Column j of A holds the coordinates of x * y^j.
    std::array<std::array<Scalar, D>, D> A;
    Elt yj = one();
    for (size_t j = 0; j < D; ++j) {
      const Elt c = mulf(x, yj);
      for (size_t i = 0; i < D; ++i) A[i][j] = c.e[i];
      Elt next = zero();
      next.e[(j + 1) % D] = f_.one();
      yj = next;
    }
    Elt z = one();
    for (size_t i = 0; i < D; ++i) {
      size_t p = i;
      while (p < D && A[p][i] == f_.zero()) ++p;
      check(p < D, "element is not invertible");
      std::swap(A[i], A[p]);
      std::swap(z.e[i], z.e[p]);
      const Scalar s = f_.invertf(A[i][i]);
      for (size_t j = 0; j < D; ++j) f_.mul(A[i][j], s);
      f_.mul(z.e[i], s);
      for (size_t k = 0; k < D; ++k) {
        if (k == i) continue;
        const Scalar a = A[k][i];
        for (size_t j = 0; j < D; ++j) f_.sub(A[k][j], f_.mulf(a, A[i][j]));
        f_.sub(z.e[k], f_.mulf(a, z.e[i]));
      }
    }
    return z;
  }

  const BaseField f_;
  Scalar alpha_;
  size_t kalpha_;  // alpha = x^kalpha_
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_GF2K_GF2_128_EXT_H_
