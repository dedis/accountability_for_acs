// GF2_128Ext (not upstream): field axioms on random elements, the defining
// relation of y, serialization, the subfield, and the coordinate-wise
// Reed-Solomon code against LCH14 over the extension itself.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "algebra/reed_solomon_componentwise.h"
#include "gf2k/gf2_128.h"
#include "gf2k/gf2_128_ext.h"
#include "gf2k/lch14_reed_solomon.h"
#include "random/transcript.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <size_t D>
void CheckField() {
  using Field = GF2_128Ext<D>;
  using Elt = typename Field::Elt;
  const Field F;
  Transcript rng((uint8_t*)"ext", 3);

  // Schoolbook product, reduced by y^2 = y + alpha or y^3 = alpha.
  auto schoolbook = [&](const Elt& x, const Elt& y) {
    const auto& B = F.base_field();
    typename Field::Scalar c[2 * D - 1];
    for (auto& ck : c) ck = B.zero();
    for (size_t i = 0; i < D; ++i) {
      for (size_t j = 0; j < D; ++j) B.add(c[i + j], B.mulf(x.e[i], y.e[j]));
    }
    for (size_t k = 2 * D - 1; k-- > D;) {
      B.add(c[k - D], B.mulf(F.alpha(), c[k]));
      if (D == 2) B.add(c[k - D + 1], c[k]);
    }
    Elt r;
    for (size_t i = 0; i < D; ++i) r.e[i] = c[i];
    return r;
  };

  // y^D reduces by the modulus.
  Elt y = F.zero();
  y.e[1] = F.base_field().one();
  Elt yd = F.one();
  for (size_t i = 0; i < D; ++i) yd = F.mulf(yd, y);
  Elt want = F.of_base(F.alpha());
  if (D == 2) want = F.addf(want, y);
  EXPECT_EQ(yd, want);

  for (size_t trial = 0; trial < 200; ++trial) {
    const Elt a = rng.elt(F), b = rng.elt(F), c = rng.elt(F);
    EXPECT_EQ(F.mulf(a, b), schoolbook(a, b));
    EXPECT_EQ(F.mulf(F.mulf(a, b), c), F.mulf(a, F.mulf(b, c)));
    EXPECT_EQ(F.mulf(a, b), F.mulf(b, a));
    EXPECT_EQ(F.mulf(a, F.addf(b, c)), F.addf(F.mulf(a, b), F.mulf(a, c)));
    EXPECT_EQ(F.mulf(a, F.one()), a);
    ASSERT_NE(a, F.zero());
    EXPECT_EQ(F.mulf(a, F.invertf(a)), F.one());

    uint8_t buf[Field::kBytes];
    F.to_bytes_field(buf, a);
    EXPECT_EQ(F.of_bytes_field(buf).value(), a);
    EXPECT_FALSE(F.in_subfield(a));

    const Elt s = rng.subfield_elt(F);
    EXPECT_TRUE(F.in_subfield(s));
    uint8_t sbuf[Field::kSubFieldBytes];
    F.to_bytes_subfield(sbuf, s);
    EXPECT_EQ(F.of_bytes_subfield(sbuf).value(), s);
  }
  // The subfield is that of the base field.
  for (uint64_t u : {0ull, 1ull, 2ull, 12345ull, 65535ull}) {
    EXPECT_EQ(F.of_scalar(u), F.of_base(F.base_field().of_scalar(u)));
  }
}

TEST(GF2_128Ext, Degree2) { CheckField<2>(); }
TEST(GF2_128Ext, Degree3) { CheckField<3>(); }

template <size_t D>
void CheckReedSolomon(size_t n, size_t m) {
  using Field = GF2_128Ext<D>;
  using Elt = typename Field::Elt;
  const Field F;
  const LCH14ReedSolomonFactory<GF2_128<>> base(F.base_field());
  const ComponentwiseReedSolomonFactory<Field, LCH14ReedSolomonFactory<GF2_128<>>>
      cw(base);
  const LCH14ReedSolomonFactory<Field> direct(F);
  Transcript rng((uint8_t*)"rs", 2);
  std::vector<Elt> got(m), want(m);
  for (size_t i = 0; i < n; ++i) got[i] = want[i] = rng.elt(F);
  cw.make(n, m)->interpolate(&got[0]);
  direct.make(n, m)->interpolate(&want[0]);
  EXPECT_EQ(got, want);
}

TEST(GF2_128Ext, ComponentwiseReedSolomon) {
  CheckReedSolomon<2>(37, 200);
  CheckReedSolomon<3>(64, 300);
}

}  // namespace
}  // namespace proofs
