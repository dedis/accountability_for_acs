// ML-DSA-65 ZK benchmark (not upstream); see ml_dsa_zk_harness.h.

#include <cstdio>

#include "circuits/tests/pq/ml_dsa/ml_dsa_65_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_zk_harness.h"
#include "util/log.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

// Category 3 (MlDsaZkCategory3).
using Harness = MlDsaZkHarness<ml_dsa::MLDsa65Params>;

Harness MakeHarness() {
  const auto example = ml_dsa_65::GetMlDsa65Examples()[0];
  return Harness(example.pkey, example.sig, example.msg, example.ctx);
}

TEST(MlDsa65ZK, ProvesAndVerifies) {
  set_log_level(ERROR);
  Harness h = MakeHarness();
  ASSERT_TRUE(h.Prove());
  EXPECT_TRUE(h.Verify());
  EXPECT_FALSE(h.Verify(/*tamper=*/true));
}

TEST(MlDsa65ZK, Soundness) {
  const ZkSoundness s = MakeHarness().Soundness();
  printf("ML-DSA-65: sumcheck %.1f proximity %.1f field %.1f linear %.1f "
         "total %.1f\n",
         s.sumcheck, s.proximity, s.field, s.linear, s.total);
  EXPECT_GE(s.total, 192);
}

void BM_MLDSA65ZK_Combined(benchmark::State& state) {
  set_log_level(ERROR);
  Harness h = MakeHarness();
  RunMlDsaZkBenchmark(state, h);
}
BENCHMARK(BM_MLDSA65ZK_Combined);

}  // namespace
}  // namespace proofs
