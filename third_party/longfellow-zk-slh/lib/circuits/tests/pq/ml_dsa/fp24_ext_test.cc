// Fp24Ext (not upstream): equal to Fp24_6 for K = 6, field axioms for
// K = 12, and the coordinate-wise Reed-Solomon code equal to
// ReedSolomonExtension6.

#include <cstddef>
#include <cstdint>
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
  std::vector<Fp24Ext<6>::Elt> got(m);
  std::vector<Fp24_6::Elt> want(m);
  for (size_t i = 0; i < n; ++i) {
    want[i] = rng.elt(F6);
    got[i] = Fp24Ext<6>::Elt{want[i].e};
  }
  cw.make(n, m)->interpolate(&got[0]);
  ext6.make(n, m)->interpolate(&want[0]);
  for (size_t i = 0; i < m; ++i) EXPECT_EQ(got[i].e, want[i].e) << i;
}

}  // namespace
}  // namespace proofs
