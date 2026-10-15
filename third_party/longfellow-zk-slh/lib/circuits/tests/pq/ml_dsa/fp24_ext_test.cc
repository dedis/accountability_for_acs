// Fp24Ext (not upstream): equal to Fp24_6 for K = 6, field axioms for
// K = 12, and the coordinate-wise Reed-Solomon code equal to
// ReedSolomonExtension6.

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/fp24.h"
#include "algebra/fp24_6.h"
#include "algebra/fp24_ext.h"
#include "algebra/reed_solomon.h"
#include "algebra/reed_solomon_componentwise.h"
#include "algebra/reed_solomon_extension.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "ligero/ligero_verifier.h"
#include "random/transcript.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

constexpr uint32_t kBeta = 7;

TEST(Fp24Ext, Degree6IsFp24_6) {
  const Fp24& q = ml_dsa::Fq();
  const Fp24_6 F6(q, kBeta);
  const Fp24Ext<6> F(q, kBeta);
  Transcript rng((uint8_t*)"fp24", 4);
  for (size_t trial = 0; trial < 200; ++trial) {
    const Fp24_6::Elt a = rng.elt(F6), b = rng.elt(F6);
    const Fp24Ext<6>::Elt x{a.e}, y{b.e};
    EXPECT_EQ(F.mulf(x, y).e, F6.mulf(a, b).e);
    EXPECT_EQ(F.invertf(x).e, F6.invertf(a).e);
  }
}

TEST(Fp24Ext, Degree12) {
  const Fp24Ext<12> F(ml_dsa::Fq(), kBeta);
  using Elt = Fp24Ext<12>::Elt;
  Transcript rng((uint8_t*)"fp24", 4);
  for (size_t trial = 0; trial < 200; ++trial) {
    const Elt a = rng.elt(F), b = rng.elt(F), c = rng.elt(F);
    EXPECT_EQ(F.mulf(F.mulf(a, b), c), F.mulf(a, F.mulf(b, c)));
    EXPECT_EQ(F.mulf(a, b), F.mulf(b, a));
    EXPECT_EQ(F.mulf(a, F.addf(b, c)), F.addf(F.mulf(a, b), F.mulf(a, c)));
    ASSERT_NE(a, F.zero());
    EXPECT_EQ(F.mulf(a, F.invertf(a)), F.one());
    uint8_t buf[Fp24Ext<12>::kBytes];
    F.to_bytes_field(buf, a);
    EXPECT_EQ(F.of_bytes_field(buf).value(), a);
  }
  // x^12 = beta.
  Elt x = F.zero();
  x.e[1] = ml_dsa::Fq().one();
  Elt x12 = F.one();
  for (size_t i = 0; i < 12; ++i) x12 = F.mulf(x12, x);
  EXPECT_EQ(x12, F.of_scalar(kBeta));
}

// Fp24::reduce, a Barrett reduction (not upstream), against %.
TEST(Fp24, ReduceMatchesRemainder) {
  const Fp24& q = ml_dsa::Fq();
  const uint64_t m = q.m_;
  std::vector<uint64_t> xs = {0,         1,         m - 1,
                              m,         m + 1,     (m - 1) * (m - 1),
                              ~uint64_t(0), ~uint64_t(0) - 1,
                              ~uint64_t(0) / m * m, ~uint64_t(0) / m * m - 1};
  uint64_t x = 0x9e3779b97f4a7c15u;
  for (size_t i = 0; i < 100000; ++i) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    xs.push_back(x);
    xs.push_back(x >> (i % 64));
  }
  for (uint64_t v : xs) EXPECT_EQ(q.reduce(v).n, v % m) << v;
}

// The Karatsuba product (not upstream) against the schoolbook product mod
// (x^12 - beta), on random elements and on all coordinates q - 1.
TEST(Fp24Ext, Degree12MatchesSchoolbook) {
  const Fp24& q = ml_dsa::Fq();
  const Fp24Ext<12> F(q, kBeta);
  using Elt = Fp24Ext<12>::Elt;
  auto schoolbook = [&](const Elt& a, const Elt& b) {
    uint64_t m[23] = {};
    for (size_t i = 0; i < 12; ++i) {
      for (size_t j = 0; j < 12; ++j) {
        m[i + j] += uint64_t(a.e[i].n) * b.e[j].n;
      }
    }
    Elt r;
    for (size_t i = 0; i < 12; ++i) {
      const uint64_t hi = i + 12 < 23 ? m[i + 12] : 0;
      r.e[i].n = static_cast<uint32_t>((m[i] + hi * kBeta) % q.m_);
    }
    return r;
  };
  Elt top;
  for (size_t i = 0; i < 12; ++i) top.e[i].n = q.m_ - 1;
  EXPECT_EQ(F.mulf(top, top), schoolbook(top, top));
  Transcript rng((uint8_t*)"fp24", 4);
  for (size_t trial = 0; trial < 1000; ++trial) {
    const Elt a = rng.elt(F), b = rng.elt(F);
    EXPECT_EQ(F.mulf(a, b), schoolbook(a, b));
    EXPECT_EQ(F.mulf(a, top), schoolbook(a, top));
  }
}

// Fp24Ext::Acc (not upstream) against sums of mulf(): 50000 terms (over two
// reductions of the coefficients), all coordinates q - 1, products by base
// elements.
TEST(Fp24Ext, AccumulatorMatchesSum) {
  const Fp24& q = ml_dsa::Fq();
  const Fp24Ext<12> F(q, kBeta);
  using Elt = Fp24Ext<12>::Elt;
  Elt top;
  for (size_t i = 0; i < 12; ++i) top.e[i].n = q.m_ - 1;
  Transcript rng((uint8_t*)"acc", 3);
  for (bool max : {false, true}) {
    auto a = F.acc();
    Elt want = F.zero();
    for (size_t i = 0; i < 50000; ++i) {
      const Elt x = max ? top : rng.elt(F), y = max ? top : rng.elt(F);
      if (i % 3 == 0) {
        const Fp24::Elt b = max ? top.e[0] : rng.elt(q);
        F.mac(a, x, b);
        F.add(want, F.mulf(x, b));
      } else {
        F.mac(a, x, y);
        F.add(want, F.mulf(x, y));
      }
      if (i % 9973 == 0) EXPECT_EQ(F.reduce(a), want) << i;
    }
    EXPECT_EQ(F.reduce(a), want);
  }
}

// ComponentwiseReedSolomon::interpolate_at (not upstream) gives the outputs
// of interpolate() at the chosen positions, for Fp24Ext<12>.
TEST(Fp24Ext, InterpolateAt) {
  const Fp24& q = ml_dsa::Fq();
  const Fp24Ext<12> F(q, kBeta);
  using Conv = CrtConvolutionFactory<CRT<1, Fp24>, Fp24>;
  using Base = ReedSolomonFactory<Fp24, Conv>;
  using CW = ComponentwiseReedSolomonFactory<Fp24Ext<12>, Base>;
  const Conv conv(q);
  const Base base(conv, q);
  const CW cw(base);
  using RS = std::remove_reference_t<decltype(*cw.make(1, 2))>;
  static_assert(InterpolatesAt<RS, Fp24Ext<12>>::value);
  Transcript rng((uint8_t*)"at", 2);
  const size_t n = 50, m = 300;
  std::vector<Fp24Ext<12>::Elt> y(m);
  for (size_t i = 0; i < n; ++i) y[i] = rng.elt(F);
  const auto rs = cw.make(n, m);
  std::vector<Fp24Ext<12>::Elt> at(5);
  const size_t pos[5] = {n, n + 1, 123, m - 2, m - 1};
  rs->interpolate_at(&y[0], 5, pos, &at[0], F);
  rs->interpolate(&y[0]);
  for (size_t t = 0; t < 5; ++t) EXPECT_EQ(at[t], y[pos[t]]) << pos[t];
}

TEST(Fp24Ext, ComponentwiseReedSolomon) {
  const Fp24& q = ml_dsa::Fq();
  const Fp24Ext<6> F(q, kBeta);
  const Fp24_6 F6(q, kBeta);
  using Conv = CrtConvolutionFactory<CRT<1, Fp24>, Fp24>;
  const Conv conv(q);
  const ReedSolomonFactory<Fp24, Conv> base(conv, q);
  const ComponentwiseReedSolomonFactory<Fp24Ext<6>,
                                        ReedSolomonFactory<Fp24, Conv>>
      cw(base);
  const ReedSolomonExtensionFactory ext6(q);
  Transcript rng((uint8_t*)"rs", 2);
  const size_t n = 50, m = 300;
  // Random messages, messages in the base field, and messages with only
  // coordinate 3 nonzero (the zero coordinates are not encoded). The
  // outputs hold other values before the encoding.
  for (size_t kind = 0; kind < 3; ++kind) {
    std::vector<Fp24Ext<6>::Elt> got(m);
    std::vector<Fp24_6::Elt> want(m);
    for (size_t i = 0; i < m; ++i) {
      want[i] = rng.elt(F6);
      if (i < n && kind > 0) {
        for (size_t d = 0; d < 6; ++d) {
          if (d != (kind == 1 ? 0 : 3)) want[i].e[d] = q.zero();
        }
      }
      got[i] = Fp24Ext<6>::Elt{want[i].e};
    }
    cw.make(n, m)->interpolate(&got[0]);
    ext6.make(n, m)->interpolate(&want[0]);
    for (size_t i = 0; i < m; ++i) {
      EXPECT_EQ(got[i].e, want[i].e) << "kind " << kind << " i " << i;
    }
  }
}

}  // namespace
}  // namespace proofs
