// Copyright 2026 Google LLC
//
// Benchmark: ProveVerify + CFT + packed status-list revocation (SHA-256 Merkle;
// SHAKE256 with PROOFS_EC_SHAKE256).

#include "circuits/tests/ec/prove_verify_revocation_shared.h"

#include <chrono>
#include <cstdint>

#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

int64_t SteadyNsSince(const std::chrono::steady_clock::time_point& t0) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now() - t0)
      .count();
}

static void BM_ProveVerifyRevocationCombined_Packed_P256(benchmark::State& state) {
  const size_t revoc_log2 = static_cast<size_t>(state.range(0));
  auto h = MakeProveVerifyRevocationHarnessP256(revoc_log2);
  for (auto _ : state) {
    const auto t_prove0 = std::chrono::steady_clock::now();
    RefreshProveVerifyRevocationShowP256(*h);
    bool proved = ProveProveVerifyRevocationP256(*h);
    const int64_t prove_ns = SteadyNsSince(t_prove0);
    benchmark::DoNotOptimize(proved);

    auto pub = PublicInputsProveVerifyRevocationP256(*h);

    const auto t_verify0 = std::chrono::steady_clock::now();
    bool verified = VerifyProveVerifyRevocationP256(*h, *pub);
    const int64_t verify_ns = SteadyNsSince(t_verify0);
    benchmark::DoNotOptimize(verified);

    state.counters["prove_ns"] = static_cast<double>(prove_ns);
    state.counters["verify_ns"] = static_cast<double>(verify_ns);
  }
}

static void RegisterProveVerifyRevocationBenchmarks() {
  constexpr int vals[] = {12, 16, 20, 24};
  for (int log2 : vals) {
    benchmark::RegisterBenchmark("BM_ProveVerifyRevocationCombined_Packed_P256",
                                 &BM_ProveVerifyRevocationCombined_Packed_P256)
        ->Args({log2});
  }
}

static const bool kRegistered = []() {
  RegisterProveVerifyRevocationBenchmarks();
  return true;
}();

}  // namespace

// The proof verifies, and fails once a bit of the public revocation root
// changes.
TEST(ProveVerifyRevocationP256, ProvesAndVerifies) {
  auto h = MakeProveVerifyRevocationHarnessP256(12);
  RefreshProveVerifyRevocationShowP256(*h);
  ASSERT_TRUE(ProveProveVerifyRevocationP256(*h));
  auto pub = PublicInputsProveVerifyRevocationP256(*h);
  EXPECT_TRUE(VerifyProveVerifyRevocationP256(*h, *pub));

  pub->v_[pub->n1_ - 1] = p256_base.of_scalar(2);
  EXPECT_FALSE(VerifyProveVerifyRevocationP256(*h, *pub));
}
}  // namespace proofs
