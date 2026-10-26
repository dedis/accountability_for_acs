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
#include <type_traits>
#include <utility>

#if defined(__aarch64__)
#include <arm_neon.h>
#endif

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
    // The largest Karatsuba intermediate: a schoolbook product of the
    // smallest size on sums of kSplit coefficients.
    check(static_cast<unsigned __int128>(K) * kSplit * q1 * q1 <
              (static_cast<unsigned __int128>(1) << 64),
          "Fp24Ext Karatsuba products may overflow");
    check(irreducible(), "x^K - beta is not irreducible");
    // Terms of an Acc before its coefficients are reduced (each below
    // K (q - 1)^2, and reduce() adds one term of at most (q - 1) beta).
    kmac_ = static_cast<size_t>(
        ((~uint64_t(0)) - uint64_t(F.m_ - 1) * beta) /
        (static_cast<uint64_t>(K) * (F.m_ - 1) * (F.m_ - 1)));
    check(kmac_ >= 2, "Fp24Ext accumulators too small");
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
    // break the BaseField abstraction
    uint64_t m[2 * K - 1];
    convolution(m, a, y);
    for (size_t i = 0; i + 1 < K; ++i) m[i] += m[i + K] * beta_;
    for (size_t i = 0; i < K; ++i) a.e[i] = f_.reduce(m[i]);
  }
  void mul(Elt& a, const Scalar& y) const {
    for (size_t i = 0; i < K; ++i) f_.mul(a.e[i], y);
  }

  // Sums of products before their reduction (not upstream): mac() adds
  // X Y, or X times a base element, to an accumulator; reduce() gives the
  // sum, the same element as the sum of mulf(). Each term adds at most
  // K (q - 1)^2 to every coefficient; after kmac_ terms the coefficients are
  // reduced mod q, so the fold of reduce() cannot overflow.
  struct Acc {
    uint64_t m[2 * K - 1];
    size_t n;
  };
  Acc acc() const { return Acc{{}, 0}; }
  void mac(Acc& a, const Elt& x, const Elt& y) const {
    uint64_t p[2 * K - 1];
    convolution(p, x, y);
    for (size_t i = 0; i < 2 * K - 1; ++i) a.m[i] += p[i];
    count(a);
  }
  void mac(Acc& a, const Elt& x, const Scalar& y) const {
    for (size_t i = 0; i < K; ++i) {
      a.m[i] += static_cast<uint64_t>(x.e[i].n) * y.n;
    }
    count(a);
  }
  // A = sum_j X[j] Y[-j] for j < N (Y read backward from Y[0]), into an
  // empty A (acc()): the same as N calls of mac(A, X[j], Y[-j]), for N
  // below kmac (not upstream; Reed-Solomon evaluation at chosen points).
  // Each term adds at most (q - 1)^2, a K-th of a product term.
  void mac_backward(Acc& a, const Elt* x, const Scalar* y, size_t n) const {
    check(a.n == 0 && n < kmac_, "mac_backward: an empty accumulator");
    uint64_t m[K] = {};
    for (size_t j = 0; j < n; ++j) {
      const uint64_t s = y[-static_cast<ptrdiff_t>(j)].n;
      for (size_t i = 0; i < K; ++i) m[i] += x[j].e[i].n * s;
    }
    for (size_t i = 0; i < K; ++i) a.m[i] = m[i];
    a.n = (n + K - 1) / K;
  }

  Elt reduce(const Acc& a) const {
    Elt r;
    for (size_t i = 0; i + 1 < K; ++i) {
      r.e[i] = f_.reduce(a.m[i] + f_.reduce(a.m[i + K]).n * uint64_t(beta_));
    }
    r.e[K - 1] = f_.reduce(a.m[K - 1]);
    return r;
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
  void count(Acc& a) const {
    if (++a.n < kmac_) return;
    for (uint64_t& m : a.m) m = f_.reduce(m).n;
    a.n = 1;
  }

  // M[0, 2K - 1) = X * Y as polynomials over the integers (not upstream):
  // for K = 12 on AArch64, a NEON schoolbook with every sum in a register
  // (about 3 times faster than Karatsuba there), else product<K>.
  static void convolution(uint64_t* m, const Elt& x, const Elt& y) {
#if defined(__aarch64__)
    if constexpr (K == 12) {
      uint32_t u[K], v[K];
      for (size_t i = 0; i < K; ++i) {
        u[i] = x.e[i].n;
        v[i] = y.e[i].n;
      }
      convolution12(m, u, v);
      return;
    }
#endif
    uint64_t u[K], v[K];
    for (size_t i = 0; i < K; ++i) {
      u[i] = x.e[i].n;
      v[i] = y.e[i].n;
    }
    product<K>(m, u, v);
  }

#if defined(__aarch64__)
  // The 12 x 12 schoolbook: the even rows of X add into E[k] = (m[2k],
  // m[2k + 1]), the odd rows into O[k] = (m[2k + 1], m[2k + 2]), 6 vector
  // multiply-adds per row; then m[2k] = E[k].0 + O[k - 1].1 and m[2k + 1] =
  // E[k].1 + O[k].0. Every sum is below 12 q^2 < 2^50.
  static void convolution12(uint64_t* m, const uint32_t* x,
                            const uint32_t* y) {
    const uint32x4_t y0 = vld1q_u32(y), y1 = vld1q_u32(y + 4),
                     y2 = vld1q_u32(y + 8);
    const uint32x2_t yv[6] = {vget_low_u32(y0), vget_high_u32(y0),
                              vget_low_u32(y1), vget_high_u32(y1),
                              vget_low_u32(y2), vget_high_u32(y2)};
    const uint32x4_t xv[3] = {vld1q_u32(x), vld1q_u32(x + 4),
                              vld1q_u32(x + 8)};
    uint64x2_t E[12], O[12];
    for (size_t k = 0; k < 12; ++k) {
      E[k] = vdupq_n_u64(0);
      O[k] = vdupq_n_u64(0);
    }
    // Row I = 4 q + 2 l (even) and I + 1 (odd), X[I] in lane 2 l of xv[q].
    auto rows = [&](const uint32x4_t& a, size_t i, auto lane) {
      constexpr int L = decltype(lane)::value;
      for (size_t j = 0; j < 6; ++j) {
        E[i / 2 + j] = vmlal_laneq_u32(E[i / 2 + j], yv[j], a, L);
        O[i / 2 + j] = vmlal_laneq_u32(O[i / 2 + j], yv[j], a, L + 1);
      }
    };
    using L0 = std::integral_constant<int, 0>;
    using L2 = std::integral_constant<int, 2>;
    rows(xv[0], 0, L0{});
    rows(xv[0], 2, L2{});
    rows(xv[1], 4, L0{});
    rows(xv[1], 6, L2{});
    rows(xv[2], 8, L0{});
    rows(xv[2], 10, L2{});
    const uint64x2_t z = vdupq_n_u64(0);
    for (size_t k = 0; k < 11; ++k) {
      const uint64x2_t odd = vextq_u64(k > 0 ? O[k - 1] : z, O[k], 1);
      vst1q_u64(&m[2 * k], vaddq_u64(E[k], odd));
    }
    m[22] = vgetq_lane_u64(E[11], 0) + vgetq_lane_u64(O[10], 1);
  }
#endif

  // 2^d for the Karatsuba depth d of product<K>.
  static constexpr size_t split(size_t n) {
    return n % 2 == 0 && n > 3 ? 2 * split(n / 2) : 1;
  }
  static constexpr size_t kSplit = split(K);

  // M[0, 2N - 1) = X * Y over the integers: Karatsuba while N is even and
  // above 3, then schoolbook. The halves are added, never subtracted, before
  // the products, so every intermediate is a nonnegative integer and M is
  // the schoolbook result (checked against overflow in the constructor).
  template <size_t N>
  static void product(uint64_t* m, const uint64_t* x, const uint64_t* y) {
    if constexpr (N % 2 != 0 || N <= 3) {
      for (size_t i = 0; i < 2 * N - 1; ++i) m[i] = 0;
      for (size_t i = 0; i < N; ++i) {
        for (size_t j = 0; j < N; ++j) m[i + j] += x[i] * y[j];
      }
    } else {
      constexpr size_t H = N / 2;
      uint64_t p0[2 * H - 1], p1[2 * H - 1], p2[2 * H - 1], sx[H], sy[H];
      product<H>(p0, x, y);
      product<H>(p2, x + H, y + H);
      for (size_t i = 0; i < H; ++i) {
        sx[i] = x[i] + x[i + H];
        sy[i] = y[i] + y[i + H];
      }
      product<H>(p1, sx, sy);
      for (size_t i = 0; i < 2 * N - 1; ++i) m[i] = 0;
      for (size_t i = 0; i < 2 * H - 1; ++i) {
        m[i] += p0[i];
        m[i + 2 * H] += p2[i];
        m[i + H] += p1[i] - p0[i] - p2[i];
      }
    }
  }

  const BaseField& f_;
  uint32_t beta_;
  size_t kmac_;  // terms of an Acc between reductions of its coefficients
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
