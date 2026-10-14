// ML-DSA-87 ZK benchmark (not upstream); see ml_dsa_zk_harness.h.

#include <cstdio>

#include "circuits/tests/pq/ml_dsa/ml_dsa_87_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_zk_harness.h"
#include "util/log.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

// Category 5 (MlDsaZkCategory5), with 64-byte digests.
using Harness = MlDsaZkHarness<ml_dsa::MLDsa87Params>;

Harness MakeHarness() {
  const auto example = ml_dsa_87::GetMlDsa87Examples()[0];
  return Harness(example.pkey, example.sig, example.msg, example.ctx);
}

TEST(MlDsa87ZK, ProvesAndVerifies) {
  set_log_level(ERROR);
  Harness h = MakeHarness();
  ASSERT_TRUE(h.Prove());
  EXPECT_TRUE(h.Verify());
  EXPECT_FALSE(h.Verify(/*tamper=*/true));
}

TEST(MlDsa87ZK, Soundness) {
  const ZkSoundness s = MakeHarness().Soundness();
  printf("ML-DSA-87: sumcheck %.1f proximity %.1f field %.1f linear %.1f "
         "total %.1f\n",
         s.sumcheck, s.proximity, s.field, s.linear, s.total);
  EXPECT_GE(s.total, 256);
}

void BM_MLDSA87ZK_Combined(benchmark::State& state) {
  set_log_level(ERROR);
  Harness h = MakeHarness();
  RunMlDsaZkBenchmark(state, h);
}
BENCHMARK(BM_MLDSA87ZK_Combined);

}  // namespace
}  // namespace proofs
