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

// Thin benchmark driver for the EC credential commitment proof (flat32, no CFT).

#include "circuits/tests/ec/prove_verify_no_cft_shared.h"

#include <chrono>

#include "benchmark/benchmark.h"

namespace proofs {
namespace {

int64_t SteadyNsSince(const std::chrono::steady_clock::time_point& t0) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now() - t0)
      .count();
}

void RebuildCredentialUntimed(CredentialCommitmentProveVerifyNoCftHarnessP256& h,
                              benchmark::State& state) {
  state.PauseTiming();
  RebuildBenchmarkCredentialNoCftP256(h);
  state.ResumeTiming();
}

}  // namespace

static void BM_CredentialCommitmentProveVerifyNoCftCombined_P256(benchmark::State& state) {
  auto h = MakeCredentialCommitmentProveVerifyNoCftHarnessP256(state.range(0));
  for (auto _ : state) {
    const auto t_prove0 = std::chrono::steady_clock::now();
    RebuildBenchmarkCredentialNoCftP256(*h);
    const bool proved = ProveVerifyNoCftP256(*h);
    const int64_t prove_ns = SteadyNsSince(t_prove0);
    benchmark::DoNotOptimize(proved);

    auto pub = PublicInputsProveVerifyNoCftP256(*h);

    const auto t_verify0 = std::chrono::steady_clock::now();
    const bool verified = VerifyProveVerifyNoCftP256(*h, *pub);
    const int64_t verify_ns = SteadyNsSince(t_verify0);
    benchmark::DoNotOptimize(verified);

    state.counters["prove_ns"] = static_cast<double>(prove_ns);
    state.counters["verify_ns"] = static_cast<double>(verify_ns);
  }
}
BENCHMARK(BM_CredentialCommitmentProveVerifyNoCftCombined_P256)->Arg(1);

static void BM_CredentialCommitmentProveVerifyNoCftProver_P256(benchmark::State& state) {
  auto h = MakeCredentialCommitmentProveVerifyNoCftHarnessP256(state.range(0));
  for (auto _ : state) {
    RebuildCredentialUntimed(*h, state);
    benchmark::DoNotOptimize(ProveVerifyNoCftP256(*h));
  }
}
BENCHMARK(BM_CredentialCommitmentProveVerifyNoCftProver_P256)->Arg(1);

static void BM_CredentialCommitmentProveVerifyNoCftVerifier_P256(benchmark::State& state) {
  auto h = MakeCredentialCommitmentProveVerifyNoCftHarnessP256(state.range(0));
  RebuildBenchmarkCredentialNoCftP256(*h);
  ProveVerifyNoCftP256(*h);
  auto pub = PublicInputsProveVerifyNoCftP256(*h);
  for (auto _ : state) {
    benchmark::DoNotOptimize(VerifyProveVerifyNoCftP256(*h, *pub));
  }
}
BENCHMARK(BM_CredentialCommitmentProveVerifyNoCftVerifier_P256)->Arg(1);

static void BM_CredentialCommitmentProveVerifyNoCftFullCycle_P256(benchmark::State& state) {
  auto h = MakeCredentialCommitmentProveVerifyNoCftHarnessP256(state.range(0));
  for (auto _ : state) {
    RebuildCredentialUntimed(*h, state);
    benchmark::DoNotOptimize(ProveAndVerifyProveVerifyNoCftP256(*h));
  }
}
BENCHMARK(BM_CredentialCommitmentProveVerifyNoCftFullCycle_P256)->Arg(1);

}  // namespace proofs
