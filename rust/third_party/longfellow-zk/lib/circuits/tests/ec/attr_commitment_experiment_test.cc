// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Benchmark driver for the "Merkle vs flat hash" experiment.

#include "circuits/tests/ec/attr_commitment_experiment_shared.h"

#include <chrono>

#include "benchmark/benchmark.h"

namespace proofs {
namespace {

int64_t SteadyNsSince(const std::chrono::steady_clock::time_point& t0) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now() - t0)
      .count();
}

// Default: one pass per repetition; prove and verify wall times exported as counters.
static void BM_AttrSigCombined_Flat(benchmark::State& state) {
  const size_t n = static_cast<size_t>(state.range(0));
  const size_t k = static_cast<size_t>(state.range(1));
  auto h = MakeAttrCommitmentExperimentHarnessP256("flat", n, k);
  for (auto _ : state) {
    const auto t_prove0 = std::chrono::steady_clock::now();
    const bool proved = ProveAttrCommitmentExperimentP256(*h);
    const int64_t prove_ns = SteadyNsSince(t_prove0);
    benchmark::DoNotOptimize(proved);

    auto pub = PublicInputsAttrCommitmentExperimentP256(*h);

    const auto t_verify0 = std::chrono::steady_clock::now();
    const bool verified = VerifyAttrCommitmentExperimentP256(*h, *pub);
    const int64_t verify_ns = SteadyNsSince(t_verify0);
    benchmark::DoNotOptimize(verified);

    state.counters["prove_ns"] = static_cast<double>(prove_ns);
    state.counters["verify_ns"] = static_cast<double>(verify_ns);
  }
}

static void BM_AttrSigCombined_Merkle(benchmark::State& state) {
  const size_t n = static_cast<size_t>(state.range(0));
  const size_t k = static_cast<size_t>(state.range(1));
  auto h = MakeAttrCommitmentExperimentHarnessP256("merkle", n, k);
  for (auto _ : state) {
    const auto t_prove0 = std::chrono::steady_clock::now();
    const bool proved = ProveAttrCommitmentExperimentP256(*h);
    const int64_t prove_ns = SteadyNsSince(t_prove0);
    benchmark::DoNotOptimize(proved);

    auto pub = PublicInputsAttrCommitmentExperimentP256(*h);

    const auto t_verify0 = std::chrono::steady_clock::now();
    const bool verified = VerifyAttrCommitmentExperimentP256(*h, *pub);
    const int64_t verify_ns = SteadyNsSince(t_verify0);
    benchmark::DoNotOptimize(verified);

    state.counters["prove_ns"] = static_cast<double>(prove_ns);
    state.counters["verify_ns"] = static_cast<double>(verify_ns);
  }
}

// Legacy split benchmarks (use BENCH_FILTER=BM_AttrSig(Prover|Verifier)_… if needed).
static void BM_AttrSigProver_Flat(benchmark::State& state) {
  const size_t n = static_cast<size_t>(state.range(0));
  const size_t k = static_cast<size_t>(state.range(1));
  auto h = MakeAttrCommitmentExperimentHarnessP256("flat", n, k);
  for (auto s : state) {
    benchmark::DoNotOptimize(ProveAttrCommitmentExperimentP256(*h));
  }
}

static void BM_AttrSigProver_Merkle(benchmark::State& state) {
  const size_t n = static_cast<size_t>(state.range(0));
  const size_t k = static_cast<size_t>(state.range(1));
  auto h = MakeAttrCommitmentExperimentHarnessP256("merkle", n, k);
  for (auto s : state) {
    benchmark::DoNotOptimize(ProveAttrCommitmentExperimentP256(*h));
  }
}

static void BM_AttrSigVerifier_Flat(benchmark::State& state) {
  const size_t n = static_cast<size_t>(state.range(0));
  const size_t k = static_cast<size_t>(state.range(1));
  auto h = MakeAttrCommitmentExperimentHarnessP256("flat", n, k);
  ProveAttrCommitmentExperimentP256(*h);
  auto pub = PublicInputsAttrCommitmentExperimentP256(*h);
  for (auto s : state) {
    benchmark::DoNotOptimize(VerifyAttrCommitmentExperimentP256(*h, *pub));
  }
}

static void BM_AttrSigVerifier_Merkle(benchmark::State& state) {
  const size_t n = static_cast<size_t>(state.range(0));
  const size_t k = static_cast<size_t>(state.range(1));
  auto h = MakeAttrCommitmentExperimentHarnessP256("merkle", n, k);
  ProveAttrCommitmentExperimentP256(*h);
  auto pub = PublicInputsAttrCommitmentExperimentP256(*h);
  for (auto s : state) {
    benchmark::DoNotOptimize(VerifyAttrCommitmentExperimentP256(*h, *pub));
  }
}

static void RegisterAttrSigExperimentBenchmarks() {
  // Must stay in sync with `MakeAttrCommitmentExperimentHarnessP256` in
  // `attr_commitment_experiment_shared.cc`: only n in {8,16,32,64} are
  // implemented, and Merkle is only built for disclosure counts k in
  // {1,2,4,8,16} (k ≤ n). Do not register k=32 or k=64 here.
  constexpr int vals_n[] = {8, 16, 32, 64};
  constexpr int vals_k[] = {1, 2, 4, 8, 16};

  for (int n : vals_n) {
    for (int k : vals_k) {
      if (k > n) continue;
      benchmark::RegisterBenchmark("BM_AttrSigCombined_Flat", &BM_AttrSigCombined_Flat)
          ->Args({n, k});
      benchmark::RegisterBenchmark("BM_AttrSigCombined_Merkle", &BM_AttrSigCombined_Merkle)
          ->Args({n, k});
      benchmark::RegisterBenchmark("BM_AttrSigProver_Flat", &BM_AttrSigProver_Flat)
          ->Args({n, k});
      benchmark::RegisterBenchmark("BM_AttrSigProver_Merkle", &BM_AttrSigProver_Merkle)
          ->Args({n, k});
      benchmark::RegisterBenchmark("BM_AttrSigVerifier_Flat", &BM_AttrSigVerifier_Flat)
          ->Args({n, k});
      benchmark::RegisterBenchmark("BM_AttrSigVerifier_Merkle", &BM_AttrSigVerifier_Merkle)
          ->Args({n, k});
    }
  }
}

static const bool kRegistered = []() {
  RegisterAttrSigExperimentBenchmarks();
  return true;
}();

}  // namespace
}  // namespace proofs
