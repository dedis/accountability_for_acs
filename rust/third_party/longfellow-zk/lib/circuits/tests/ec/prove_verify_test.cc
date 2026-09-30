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

// Thin benchmark driver for the EC credential commitment proof.
// Shared circuit + witness logic lives in `prove_verify_shared.cc`.

#include "circuits/tests/ec/prove_verify_shared.h"

#include <chrono>

#include "benchmark/benchmark.h"

namespace proofs {
namespace {

int64_t SteadyNsSince(const std::chrono::steady_clock::time_point& t0) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now() - t0)
      .count();
}

void RebuildCredentialUntimed(CredentialCommitmentProveVerifyHarnessP256& h,
                              benchmark::State& state) {
  state.PauseTiming();
  RebuildBenchmarkCredentialP256(h);
  state.ResumeTiming();
}

}  // namespace

// Default: one pass per repetition; prove and verify wall times exported as counters.
// prove_ns = refresh_show_inputs() + fill_input() + Ligero (per-show native prep + ZK).
static void BM_CredentialCommitmentProveVerifyCombined_P256(benchmark::State& state) {
  auto h = MakeCredentialCommitmentProveVerifyHarnessP256(state.range(0));
  for (auto _ : state) {
    const auto t_prove0 = std::chrono::steady_clock::now();
    RebuildBenchmarkCredentialP256(*h);
    const bool proved = ProveVerifyP256(*h);
    const int64_t prove_ns = SteadyNsSince(t_prove0);
    benchmark::DoNotOptimize(proved);

    auto pub = PublicInputsProveVerifyP256(*h);

    const auto t_verify0 = std::chrono::steady_clock::now();
    const bool verified = VerifyProveVerifyP256(*h, *pub);
    const int64_t verify_ns = SteadyNsSince(t_verify0);
    benchmark::DoNotOptimize(verified);

    state.counters["prove_ns"] = static_cast<double>(prove_ns);
    state.counters["verify_ns"] = static_cast<double>(verify_ns);
  }
}
BENCHMARK(BM_CredentialCommitmentProveVerifyCombined_P256)->Arg(1);

// Legacy split benchmarks (use --benchmark_filter if you need them separately).
static void BM_CredentialCommitmentProveVerifyProver_P256(benchmark::State& state) {
  auto h = MakeCredentialCommitmentProveVerifyHarnessP256(state.range(0));
  for (auto _ : state) {
    RebuildCredentialUntimed(*h, state);
    benchmark::DoNotOptimize(ProveVerifyP256(*h));
  }
}
BENCHMARK(BM_CredentialCommitmentProveVerifyProver_P256)->Arg(1);

static void BM_CredentialCommitmentProveVerifyVerifier_P256(benchmark::State& state) {
  auto h = MakeCredentialCommitmentProveVerifyHarnessP256(state.range(0));
  RebuildBenchmarkCredentialP256(*h);
  ProveVerifyP256(*h);
  auto pub = PublicInputsProveVerifyP256(*h);
  for (auto _ : state) {
    benchmark::DoNotOptimize(VerifyProveVerifyP256(*h, *pub));
  }
}
BENCHMARK(BM_CredentialCommitmentProveVerifyVerifier_P256)->Arg(1);

static void BM_CredentialCommitmentProveVerifyFullCycle_P256(benchmark::State& state) {
  auto h = MakeCredentialCommitmentProveVerifyHarnessP256(state.range(0));
  for (auto _ : state) {
    RebuildCredentialUntimed(*h, state);
    benchmark::DoNotOptimize(ProveAndVerifyProveVerifyP256(*h));
  }
}
BENCHMARK(BM_CredentialCommitmentProveVerifyFullCycle_P256)->Arg(1);

}  // namespace proofs
