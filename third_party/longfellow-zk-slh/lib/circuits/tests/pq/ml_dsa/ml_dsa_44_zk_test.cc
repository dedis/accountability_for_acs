// ML-DSA-44 ZK benchmark (not upstream); see ml_dsa_zk_harness.h.

#include <cstddef>
#include <cstdio>

#include "algebra/fp24_ext.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_zk_harness.h"
#include "util/log.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

// Category 2: at least 128 bits, with the 48-byte digests of this program
// (32 bytes would do).
struct MlDsaZkCategory2 {
  using Field = Fp24Ext<12>;
  static constexpr size_t kDegree = 12;
  static constexpr size_t kQueries = 181;
  static constexpr size_t kDigestBytes = 48;
};

using Harness = MlDsaZkHarness<ml_dsa::MLDsa44Params, MlDsaZkCategory2>;

Harness MakeHarness() {
  const auto example = ml_dsa::GetMlDsa44Examples()[0];
  return Harness(example.pkey, example.sig, example.msg, example.ctx);
}

TEST(MlDsa44ZK, ProvesAndVerifies) {
  set_log_level(ERROR);
  Harness h = MakeHarness();
  ASSERT_TRUE(h.Prove());
  EXPECT_TRUE(h.Verify());
  EXPECT_FALSE(h.Verify(/*tamper=*/true));
}

TEST(MlDsa44ZK, Soundness) {
  const ZkSoundness s = MakeHarness().Soundness();
  printf("ML-DSA-44: sumcheck %.1f proximity %.1f field %.1f linear %.1f "
         "total %.1f\n",
         s.sumcheck, s.proximity, s.field, s.linear, s.total);
  EXPECT_GE(s.total, 128);
}

void BM_MLDSA44ZK_Combined(benchmark::State& state) {
  set_log_level(ERROR);
  Harness h = MakeHarness();
  RunMlDsaZkBenchmark(state, h);
}
BENCHMARK(BM_MLDSA44ZK_Combined);

}  // namespace
}  // namespace proofs
