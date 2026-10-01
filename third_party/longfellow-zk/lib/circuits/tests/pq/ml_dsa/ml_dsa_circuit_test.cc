// Copyright 2026 Google LLC.
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

#include "circuits/tests/pq/ml_dsa/ml_dsa_circuit.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "algebra/fp24.h"
#include "algebra/fp24_6.h"
#include "algebra/reed_solomon_extension.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_65_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_witness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using BaseField = Fp24;
using Field6 = Fp24_6;
using CBK = CompilerBackend<Field6>;
using LogicCircuit = Logic<Field6, CBK>;

constexpr uint32_t kBeta = 7;

template <typename Params>
struct MLDsaCircuitTestTraits;

template <>
struct MLDsaCircuitTestTraits<ml_dsa::MLDsa44Params> {
  static constexpr size_t kCPrimeTildeBlocks = 7;
  using Params = ml_dsa::MLDsa44Params;
  using VerifyCircuit = MLDSAVerify<LogicCircuit, Field6, Params>;
  using WitnessGen = ml_dsa_witness<Params>;
  static std::vector<ml_dsa::MlDsa44SignatureExample> GetExamples() {
    return ml_dsa::GetMlDsa44Examples();
  }
  static const char* Name() { return "ml_dsa_44"; }
};

template <>
struct MLDsaCircuitTestTraits<ml_dsa::MLDsa65Params> {
  static constexpr size_t kCPrimeTildeBlocks = 7;
  using Params = ml_dsa::MLDsa65Params;
  using VerifyCircuit = MLDSAVerify<LogicCircuit, Field6, Params>;
  using WitnessGen = ml_dsa_witness<Params>;
  static std::vector<ml_dsa_65::MlDsa65SignatureExample> GetExamples() {
    return ml_dsa_65::GetMlDsa65Examples();
  }
  static const char* Name() { return "ml_dsa_65"; }
};

// Helper function to build an ML-DSA circuit. It sets up the circuit builder
// environment (QuadCircuit, LogicCircuit) and instantiates the MLDSAVerify
// helper, then applies the provided function `f` to define the circuit's
// inputs and constraints. This is used to build both individual sub-circuits
// and the full verification circuit.
template <typename Params, typename F>
std::unique_ptr<Circuit<Field6>> build_ml_dsa_circuit(size_t nc,
                                                      const char* name, F f) {
  const Field6 f6 = Field6(ml_dsa::Fq(), kBeta);

  QuadCircuit<Field6> Q(f6);
  const CBK cbk(&Q);
  const LogicCircuit LC(&cbk, f6);
  MLDSAVerify<LogicCircuit, Field6, Params> verify(LC);

  f(Q, LC, verify);

  auto CIRCUIT = Q.mkcircuit(nc);
  dump_info(name, Q);
  return CIRCUIT;
}

// Builds the full ML-DSA signature verification circuit that verifies a
// signature against a public key and a message hash (mu).
template <typename Params>
std::unique_ptr<Circuit<Field6>> make_ml_dsa_circuit(size_t nc) {
  using Traits = MLDsaCircuitTestTraits<Params>;
  using VerifyCircuit = typename Traits::VerifyCircuit;
  std::string name = std::string(Traits::Name()) + "_valid_signature_on_mu";
  return build_ml_dsa_circuit<Params>(
      nc, name.c_str(),
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        auto pk = std::make_unique<typename VerifyCircuit::Pk>();
        pk->input(LC);

        Q.private_input();
        auto sig = std::make_unique<typename VerifyCircuit::SignatureW>();
        sig->input(LC);

        auto w = std::make_unique<typename VerifyCircuit::Witness>();
        w->c_prime_tilde_bws_.resize(Traits::kCPrimeTildeBlocks);

        w->input(LC);

        std::array<LogicCircuit::v8, 64> mu;
        for (size_t i = 0; i < 64; ++i) {
          mu[i] = LC.vinput<8>();
        }

        verify.assert_valid_signature_on_mu(*pk, *sig, mu, *w);
      });
}

template <typename Params>
std::unique_ptr<Circuit<Field6>> make_ml_dsa_sampleinball_circuit(size_t nc) {
  using Traits = MLDsaCircuitTestTraits<Params>;
  using VerifyCircuit = typename Traits::VerifyCircuit;
  std::string name = std::string(Traits::Name()) + "_sample_in_ball";
  return build_ml_dsa_circuit<Params>(
      nc, name.c_str(),
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        std::array<LogicCircuit::v8, Params::c_tilde_bytes> rho;
        for (size_t i = 0; i < Params::c_tilde_bytes; ++i) {
          rho[i] = LC.vinput<8>();
        }

        Q.private_input();

        typename VerifyCircuit::RqW cprime;
        cprime.input(LC);

        typename VerifyCircuit::SampleInBallWitness witness;
        witness.input(LC);

        verify.assert_sample_in_ball(rho, cprime, witness);
      });
}

template <typename Params>
std::unique_ptr<Circuit<Field6>> make_ml_dsa_w_prime_approx_circuit(size_t nc) {
  using Traits = MLDsaCircuitTestTraits<Params>;
  using VerifyCircuit = typename Traits::VerifyCircuit;
  std::string name = std::string(Traits::Name()) + "_w_prime_approx";
  return build_ml_dsa_circuit<Params>(
      nc, name.c_str(),
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        auto pk = std::make_unique<typename VerifyCircuit::Pk>();
        pk->input(LC);

        Q.private_input();
        auto sig = std::make_unique<typename VerifyCircuit::SignatureW>();
        sig->input(LC);

        auto w = std::make_unique<typename VerifyCircuit::Witness>();
        w->c_prime_tilde_bws_.resize(Traits::kCPrimeTildeBlocks);

        w->input(LC);

        verify.assert_w_prime_approx(*pk, *sig, *w);
      });
}

template <typename Params>
std::unique_ptr<Circuit<Field6>> make_ml_dsa_use_hint_circuit(size_t nc) {
  using Traits = MLDsaCircuitTestTraits<Params>;
  using VerifyCircuit = typename Traits::VerifyCircuit;
  std::string name = std::string(Traits::Name()) + "_use_hint";
  return build_ml_dsa_circuit<Params>(
      nc, name.c_str(),
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        Q.private_input();
        auto sig = std::make_unique<typename VerifyCircuit::SignatureW>();
        sig->input(LC);

        auto w = std::make_unique<typename VerifyCircuit::Witness>();
        w->input(LC);

        verify.assert_use_hint(sig->h, w->w_prime_approx_, w->w1_, w->w1_bits_,
                               w->hint_aux_bits_, w->w_prime_1_,
                               w->w_prime_1_bits_, w->h_sum_bits_);
      });
}

template <typename Params>
std::unique_ptr<Circuit<Field6>> make_ml_dsa_ctilde_circuit(size_t nc) {
  using Traits = MLDsaCircuitTestTraits<Params>;
  using VerifyCircuit = typename Traits::VerifyCircuit;
  std::string name = std::string(Traits::Name()) + "_ctilde";
  return build_ml_dsa_circuit<Params>(
      nc, name.c_str(),
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        Q.private_input();
        auto sig = std::make_unique<typename VerifyCircuit::SignatureW>();
        sig->input(LC);

        auto w = std::make_unique<typename VerifyCircuit::Witness>();
        w->c_prime_tilde_bws_.resize(Traits::kCPrimeTildeBlocks);
        w->input(LC);

        std::array<LogicCircuit::v8, 64> mu;
        for (size_t i = 0; i < 64; ++i) {
          mu[i] = LC.vinput<8>();
        }

        verify.assert_ctilde(mu, w->w1_tilde_, w->c_prime_tilde_bws_,
                             sig->c_tilde);
      });
}

template <typename Params>
std::unique_ptr<Circuit<Field6>> make_ml_dsa_infty_norm_circuit(size_t nc) {
  using Traits = MLDsaCircuitTestTraits<Params>;
  using VerifyCircuit = typename Traits::VerifyCircuit;
  std::string name = std::string(Traits::Name()) + "_infty_norm";
  return build_ml_dsa_circuit<Params>(
      nc, name.c_str(),
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        Q.private_input();
        std::array<typename VerifyCircuit::RqW, Params::L> z;
        for (size_t i = 0; i < Params::L; ++i) {
          z[i].input(LC);
        }
        std::array<
            std::array<typename LogicCircuit::template bitvec<Params::z_bits>,
                       ml_dsa::N>,
            Params::L>
            z_bits;
        for (size_t i = 0; i < Params::L; ++i) {
          for (size_t j = 0; j < ml_dsa::N; ++j) {
            z_bits[i][j] = LC.template vinput<Params::z_bits>();
          }
        }
        verify.template assert_infty_norm<Params::L, Params::z_bits>(
            z, z_bits, Params::gamma_1 - Params::beta);
      });
}

template <typename Params>
std::unique_ptr<Circuit<Field6>> make_ml_dsa_use_hint_single_circuit(
    size_t nc) {
  using Traits = MLDsaCircuitTestTraits<Params>;
  using VerifyCircuit = typename Traits::VerifyCircuit;
  std::string name = std::string(Traits::Name()) + "_use_hint_single";
  return build_ml_dsa_circuit<Params>(
      nc, name.c_str(),
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        Q.private_input();
        typename LogicCircuit::EltW h_elt = LC.eltw_input();
        typename LogicCircuit::EltW r_elt = LC.eltw_input();
        typename LogicCircuit::EltW r1_raw = LC.eltw_input();
        typename LogicCircuit::template bitvec<Params::r1_bits>
            r1_raw_bits_elt = LC.template vinput<Params::r1_bits>();
        typename LogicCircuit::template bitvec<Params::r0_bits + 1>
            hint_r0_bits_elt = LC.template vinput<Params::r0_bits + 1>();
        typename LogicCircuit::EltW hinted_r1 = LC.eltw_input();
        typename LogicCircuit::template bitvec<Params::r1_bits> r1_bits_elt =
            LC.template vinput<Params::r1_bits>();

        verify.assert_use_hint_single(h_elt, r_elt, r1_raw, r1_raw_bits_elt,
                                      hint_r0_bits_elt, hinted_r1, r1_bits_elt);
      });
}

template <typename T>
class MlDsaCircuitTest : public ::testing::Test {
 public:
  using Params = T;
  using Traits = MLDsaCircuitTestTraits<Params>;
};

using MlDsaCircuitTestTypes =
    ::testing::Types<ml_dsa::MLDsa44Params, ml_dsa::MLDsa65Params>;
TYPED_TEST_SUITE(MlDsaCircuitTest, MlDsaCircuitTestTypes);

TYPED_TEST(MlDsaCircuitTest, SampleInBallCircuitSize) {
  using Params = typename TestFixture::Params;
  auto CIRCUIT = make_ml_dsa_sampleinball_circuit<Params>(1);
}

TYPED_TEST(MlDsaCircuitTest, WPrimeApproxCircuitSize) {
  using Params = typename TestFixture::Params;
  auto CIRCUIT = make_ml_dsa_w_prime_approx_circuit<Params>(1);
}

TYPED_TEST(MlDsaCircuitTest, UseHintCircuitSize) {
  using Params = typename TestFixture::Params;
  auto CIRCUIT = make_ml_dsa_use_hint_circuit<Params>(1);
}

TYPED_TEST(MlDsaCircuitTest, CTildeCircuitSize) {
  using Params = typename TestFixture::Params;
  auto CIRCUIT = make_ml_dsa_ctilde_circuit<Params>(1);
}

template <typename Params>
struct ProverEnv {
  using Traits = MLDsaCircuitTestTraits<Params>;
  const Field6& f;
  std::unique_ptr<Circuit<Field6>> circuit;
  ReedSolomonExtensionFactory rsextf;
  typename Traits::WitnessGen witness_gen;
  std::unique_ptr<ZkProof<Field6>> zkpr;
  Dense<Field6> w;
  ZkProver<Field6, ReedSolomonExtensionFactory> prover;
  Transcript tp;
  SecureRandomEngine rng;

  explicit ProverEnv(const Field6& f6)
      : f(f6),
        circuit(make_ml_dsa_circuit<Params>(1)),
        rsextf(ml_dsa::Fq()),
        w(1, circuit->ninputs),
        prover(*circuit, f, rsextf),
        tp((uint8_t*)"test", 4) {
    auto tests = Traits::GetExamples();
    const auto& test = tests[0];
    witness_gen.compute_witness(test.pkey, test.sig, test.msg, test.ctx);

    zkpr = std::make_unique<ZkProof<Field6>>(*circuit, 4, 128);
    DenseFiller<Field6> filler(w);
    filler.push_back(f.one());
    witness_gen.fill_witness(filler, f);

    for (size_t i = 0; i < 64; ++i) {
      filler.push_back(witness_gen.mu_[i], 8, f);
    }
  }
};

TYPED_TEST(MlDsaCircuitTest, AssertValidSignatureOnMu) {
  using Params = typename TestFixture::Params;
  const Field6 f = Field6(ml_dsa::Fq(), kBeta);
  ProverEnv<Params> env(f);

  env.prover.commit(*env.zkpr, env.w, env.tp, env.rng);
  bool ok = env.prover.prove(*env.zkpr, env.w, env.tp);
  EXPECT_TRUE(ok) << "Failed to prove witness for test case ";

  ZkVerifier<Field6, ReedSolomonExtensionFactory> verifier(
      *env.circuit, env.rsextf, 4, 128, env.f);
  Transcript tv((uint8_t*)"test", 4);
  verifier.recv_commitment(*env.zkpr, tv);
  Dense<Field6> pub(1, env.circuit->ninputs);
  DenseFiller<Field6> vfiller(pub);
  vfiller.push_back(env.f.one());
  env.witness_gen.fill_pk(vfiller, env.f);

  bool ok2 = verifier.verify(*env.zkpr, pub, tv);
  EXPECT_TRUE(ok2) << "Failed to verify witness for test case ";
}

TYPED_TEST(MlDsaCircuitTest, InftyNormInvalidBoundRejected) {
  using Params = typename TestFixture::Params;
  const Field6 f = Field6(ml_dsa::Fq(), kBeta);

  auto circuit = make_ml_dsa_infty_norm_circuit<Params>(1);

  uint64_t bound = Params::gamma_1 - Params::beta;
  uint64_t bad_val = ml_dsa::Q - bound;

  Dense<Field6> w(1, circuit->ninputs);
  DenseFiller<Field6> filler(w);
  filler.push_back(f.one());  // public input 1

  // z has L polynomials, each N coefficients.
  // We set the first coefficient of the first polynomial to bad_val, and others
  // to 0.
  filler.push_back(f.of_scalar(bad_val));
  for (size_t i = 1; i < Params::L * ml_dsa::N; ++i) {
    filler.push_back(f.zero());
  }

  for (size_t b = 0; b < Params::z_bits; ++b) {
    filler.push_back(f.zero());
  }

  // For others, z_i = 0, so shifted is 0 + bound = bound.
  // We provide the bits of bound.
  for (size_t i = 1; i < Params::L * ml_dsa::N; ++i) {
    for (size_t b = 0; b < Params::z_bits; ++b) {
      bool bit = (bound >> b) & 1;
      filler.push_back(bit ? f.one() : f.zero());
    }
  }

  // Verify that the circuit REJECTS this invalid witness.
  ZkProof<Field6> zkpr(*circuit, 4, 128);
  Transcript tp((uint8_t*)"test", 4);
  SecureRandomEngine rng;

  ReedSolomonExtensionFactory rsextf(ml_dsa::Fq());
  ZkProver<Field6, ReedSolomonExtensionFactory> prover(*circuit, f, rsextf);
  prover.commit(zkpr, w, tp, rng);
  bool ok = prover.prove(zkpr, w, tp);

  EXPECT_FALSE(ok) << "Circuit accepted invalid z = -bound (soundness bug!)";
}

TYPED_TEST(MlDsaCircuitTest, UseHintInvalidSignRejected) {
  using Params = typename TestFixture::Params;
  const Field6 f = Field6(ml_dsa::Fq(), kBeta);

  auto circuit = make_ml_dsa_use_hint_single_circuit<Params>(1);

  // We choose a case where h = 1 and r_0 > 0.
  // Let r_0 = 1.
  // Let r_1 = 5.
  // So r = r_1 * 2*gamma_2 + r_0 = 5 * 2*gamma_2 + 1.
  // Since r_0 > 0, the correct w'_1 is (r_1 + 1) mod M = 6.
  // The correct s_bit is 0.
  //
  // We cheat by setting s_bit = 1 (claiming r_0 <= 0), which forces w'_1 = r_1
  // - 1 = 4. We want to show the circuit accepts this.

  uint64_t r0 = 1;
  uint64_t r1 = 5;
  uint64_t two_gamma2 = 2 * Params::gamma_2;
  uint64_t r = (r1 * two_gamma2 + r0) % ml_dsa::Q;
  uint64_t hinted_r1_cheat = r1 - 1;  // 4 (should be 6)
  uint64_t s_bit_cheat = 1;           // 1 (should be 0)

  // r0_shifted = r_0 + gamma_2 = 1 + gamma_2.
  uint64_t r0_shifted = Params::gamma_2 + 1;

  Dense<Field6> w(1, circuit->ninputs);
  DenseFiller<Field6> filler(w);
  filler.push_back(f.one());  // public input 1

  // Inputs:
  // 1. h_elt (hint bit) = 1
  filler.push_back(f.one());
  // 2. r_elt (approximate w) = r
  filler.push_back(f.of_scalar(r));
  // 3. r1_raw (prover claimed r1) = r1 (5)
  filler.push_back(f.of_scalar(r1));

  // 4. hint_r0_bits_elt (r0_bits + 1 bits)
  // first r0_bits bits are r0_shifted (gamma_2)
  for (size_t b = 0; b < Params::r0_bits; ++b) {
    bool bit = (r0_shifted >> b) & 1;
    filler.push_back(bit ? f.one() : f.zero());
  }
  // the last bit is s_bit_cheat (1)
  filler.push_back(s_bit_cheat ? f.one() : f.zero());

  // 5. hinted_r1 (w'_1) = hinted_r1_cheat (4)
  filler.push_back(f.of_scalar(hinted_r1_cheat));

  // 6. r1_bits_elt (R1_BITS bits of hinted_r1_cheat)
  for (size_t b = 0; b < Params::r1_bits; ++b) {
    bool bit = (hinted_r1_cheat >> b) & 1;
    filler.push_back(bit ? f.one() : f.zero());
  }

  // Verify that the circuit REJECTS this invalid witness.
  ZkProof<Field6> zkpr(*circuit, 4, 128);
  Transcript tp((uint8_t*)"test", 4);
  SecureRandomEngine rng;

  ReedSolomonExtensionFactory rsextf(ml_dsa::Fq());
  ZkProver<Field6, ReedSolomonExtensionFactory> prover(*circuit, f, rsextf);
  prover.commit(zkpr, w, tp, rng);
  bool ok = prover.prove(zkpr, w, tp);

  EXPECT_FALSE(ok)
      << "Circuit accepted invalid UseHint witness (soundness bug!)";
}

void BM_MLDSA44ZK_Prove(benchmark::State& state) {
  set_log_level(ERROR);
  const Field6& f = Field6(ml_dsa::Fq(), kBeta);

  ProverEnv<ml_dsa::MLDsa44Params> env(f);

  for (auto s : state) {
    env.prover.commit(*env.zkpr, env.w, env.tp, env.rng);
    env.prover.prove(*env.zkpr, env.w, env.tp);
    benchmark::DoNotOptimize(env.zkpr);
  }
}
BENCHMARK(BM_MLDSA44ZK_Prove);

void BM_MLDSA65ZK_Prove(benchmark::State& state) {
  set_log_level(ERROR);
  const Field6& f = Field6(ml_dsa::Fq(), kBeta);

  ProverEnv<ml_dsa::MLDsa65Params> env(f);

  for (auto s : state) {
    env.prover.commit(*env.zkpr, env.w, env.tp, env.rng);
    env.prover.prove(*env.zkpr, env.w, env.tp);
    benchmark::DoNotOptimize(env.zkpr);
  }
}
BENCHMARK(BM_MLDSA65ZK_Prove);

}  // namespace
}  // namespace proofs
