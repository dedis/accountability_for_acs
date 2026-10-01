// ML-DSA-65 counterpart of BM_CredentialCommitmentProveVerifyCombined_P256
// (circuits/tests/ec/prove_verify_test.cc): one pass per repetition, prove and
// verify wall times exported as the prove_ns and verify_ns counters.
//
// The statement is upstream's: a valid ML-DSA-65 signature on a private mu,
// under a public key. The circuit and the Ligero parameters (rate 4, 128
// queries) are those of make_ml_dsa_circuit and ProverEnv in
// ml_dsa_circuit_test.cc.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "algebra/fp24.h"
#include "algebra/fp24_6.h"
#include "algebra/reed_solomon_extension.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_65_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_65_witness.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_circuit.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/panic.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field6 = Fp24_6;
using LogicCircuit = Logic<Field6, CompilerBackend<Field6>>;
using Params = ml_dsa::MLDsa65Params;
using Verify = MLDSAVerify<LogicCircuit, Field6, Params>;

constexpr uint32_t kBeta = 7;
constexpr size_t kCPrimeTildeBlocks = 7;
constexpr size_t kRate = 4;
constexpr size_t kQueries = 128;

std::unique_ptr<Circuit<Field6>> make_circuit(const Field6& f) {
  QuadCircuit<Field6> Q(f);
  const CompilerBackend<Field6> cbk(&Q);
  const LogicCircuit LC(&cbk, f);
  Verify verify(LC);

  auto pk = std::make_unique<Verify::Pk>();
  pk->input(LC);

  Q.private_input();
  auto sig = std::make_unique<Verify::SignatureW>();
  sig->input(LC);

  auto w = std::make_unique<Verify::Witness>();
  w->c_prime_tilde_bws_.resize(kCPrimeTildeBlocks);
  w->input(LC);

  std::array<LogicCircuit::v8, 64> mu;
  for (size_t i = 0; i < 64; ++i) mu[i] = LC.vinput<8>();

  verify.assert_valid_signature_on_mu(*pk, *sig, mu, *w);
  return Q.mkcircuit(/*nc=*/1);
}

int64_t SteadyNsSince(const std::chrono::steady_clock::time_point& t0) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now() - t0)
      .count();
}

struct Harness {
  const Field6 f{ml_dsa::Fq(), kBeta};
  const ReedSolomonExtensionFactory rsf{ml_dsa::Fq()};
  const std::unique_ptr<Circuit<Field6>> circuit = make_circuit(f);
  const ml_dsa_65::MlDsa65SignatureExample example =
      ml_dsa_65::GetMlDsa65Examples()[0];
  SecureRandomEngine rng;
  std::unique_ptr<ZkProof<Field6>> zkpr;
  std::unique_ptr<ml_dsa_65_witness> witness;

  // Witness computation from the encoded key, signature and message, then
  // commit and prove. compute_witness appends to its block witnesses, so each
  // proof starts from a fresh witness.
  bool Prove() {
    witness = std::make_unique<ml_dsa_65_witness>();
    check(witness->compute_witness(example.pkey, example.sig, example.msg,
                                  example.ctx),
          "ML-DSA-65 witness computation failed");
    Dense<Field6> w(1, circuit->ninputs);
    DenseFiller<Field6> filler(w);
    filler.push_back(f.one());
    witness->fill_witness(filler, f);
    for (uint8_t b : witness->mu_) filler.push_back(b, 8, f);
    check(filler.size() == circuit->ninputs,
          "input count does not match the circuit");

    zkpr = std::make_unique<ZkProof<Field6>>(*circuit, kRate, kQueries);
    ZkProver<Field6, ReedSolomonExtensionFactory> prover(*circuit, f, rsf);
    Transcript tp((uint8_t*)"test", 4);
    prover.commit(*zkpr, w, tp, rng);
    return prover.prove(*zkpr, w, tp);
  }

  // The verifier knows only the public key.
  bool Verify() const {
    Dense<Field6> pub(1, circuit->ninputs);
    DenseFiller<Field6> filler(pub);
    filler.push_back(f.one());
    witness->fill_pk(filler, f);

    ZkVerifier<Field6, ReedSolomonExtensionFactory> verifier(
        *circuit, rsf, kRate, kQueries, f);
    Transcript tv((uint8_t*)"test", 4);
    verifier.recv_commitment(*zkpr, tv);
    return verifier.verify(*zkpr, pub, tv);
  }
};

TEST(MlDsa65ZK, ProvesAndVerifies) {
  set_log_level(ERROR);
  Harness h;
  ASSERT_TRUE(h.Prove());
  EXPECT_TRUE(h.Verify());
}

void BM_MLDSA65ZK_Combined(benchmark::State& state) {
  set_log_level(ERROR);
  Harness h;
  for (auto _ : state) {
    const auto t_prove0 = std::chrono::steady_clock::now();
    const bool proved = h.Prove();
    const int64_t prove_ns = SteadyNsSince(t_prove0);
    check(proved, "ML-DSA-65 proof failed");

    const auto t_verify0 = std::chrono::steady_clock::now();
    const bool verified = h.Verify();
    const int64_t verify_ns = SteadyNsSince(t_verify0);
    check(verified, "ML-DSA-65 proof did not verify");

    state.counters["prove_ns"] = static_cast<double>(prove_ns);
    state.counters["verify_ns"] = static_cast<double>(verify_ns);
  }
}
BENCHMARK(BM_MLDSA65ZK_Combined);

}  // namespace
}  // namespace proofs
