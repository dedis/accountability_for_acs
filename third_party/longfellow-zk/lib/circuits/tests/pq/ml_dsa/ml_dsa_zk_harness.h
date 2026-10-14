// Prove/verify harness of the ML-DSA ZK benchmarks (not upstream), the
// counterpart of BM_CredentialCommitmentProveVerifyCombined_P256
// (circuits/tests/ec/prove_verify_test.cc): one pass per repetition, prove and
// verify wall times exported as the prove_ns and verify_ns counters, and the
// serialized proof size as proof_bytes.
//
// The statement is upstream's: a valid ML-DSA signature on a private mu,
// under a public key. The circuit is that of make_ml_dsa_circuit in
// ml_dsa_circuit_test.cc. The proof field and the Ligero queries (rate 4)
// follow the NIST category (MlDsaZkCategory3, MlDsaZkCategory5 below).

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_ZK_HARNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_ZK_HARNESS_H_

#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/fp24.h"
#include "algebra/fp24_ext.h"
#include "algebra/reed_solomon.h"
#include "algebra/reed_solomon_componentwise.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_circuit.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_witness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/crypto.h"
#include "util/readbuffer.h"
#include "util/panic.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_soundness.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"

namespace proofs {

// Proof field (an extension of Fq, q = 8380417), Ligero queries (rate 4)
// and SHAKE256 digest size of a NIST category. ml_dsa_*_zk_test checks the
// soundness bits (zk/zk_soundness.h).
//   MlDsaZkCategory3: Fq^12 (276 bits), 274 queries, 48-byte digests: at
//                     least 192 bits.
//   MlDsaZkCategory5: Fq^12, 362 queries, 64-byte digests: at least 256 bits
//                     (the field terms give 263 bits).
// The digest size is fixed per program (PROOFS_SHAKE256_DIGEST_BYTES).
struct MlDsaZkCategory3 {
  using Field = Fp24Ext<12>;
  static constexpr size_t kDegree = 12;
  static constexpr size_t kQueries = 274;
  static constexpr size_t kDigestBytes = 48;
};
struct MlDsaZkCategory5 {
  using Field = Fp24Ext<12>;
  static constexpr size_t kDegree = 12;
  static constexpr size_t kQueries = 362;
  static constexpr size_t kDigestBytes = 64;
};
// ML-DSA-87 (K = 8) is category 5; ML-DSA-44 and ML-DSA-65 get category 3.
template <typename Params>
using MlDsaZkDefault =
    std::conditional_t<Params::K == 8, MlDsaZkCategory5, MlDsaZkCategory3>;

// The Reed-Solomon code of a proof field: over Fq, coordinate by coordinate.
template <class Field>
struct MlDsaRs {
  using Conv = CrtConvolutionFactory<CRT<1, Fp24>, Fp24>;
  using Base = ReedSolomonFactory<Fp24, Conv>;
  using Factory = ComponentwiseReedSolomonFactory<Field, Base>;
  explicit MlDsaRs(const Fp24& f) : conv(f), base(conv, f), factory(base) {}
  const Conv conv;
  const Base base;
  const Factory factory;
};

template <typename Params, class Z = MlDsaZkDefault<Params>>
class MlDsaZkHarness {
  static_assert(kHashDigestSize == Z::kDigestBytes,
                "build with PROOFS_SHAKE256_DIGEST_BYTES = Z::kDigestBytes");

 public:
  using Field = typename Z::Field;

 private:
  using LogicCircuit = Logic<Field, CompilerBackend<Field>>;
  using VerifyCircuit = MLDSAVerify<LogicCircuit, Field, Params>;
  using RSFactory = typename MlDsaRs<Field>::Factory;

  static constexpr uint32_t kBeta = 7;
  static constexpr size_t kRate = 4;
  static constexpr size_t kQueries = Z::kQueries;
  // Keccak-f calls of SHAKE256(mu || w1Encode(w'_1)), whose output fits in
  // one block (Sha3Circuit::assert_shake256).
  static constexpr size_t kCPrimeTildeBlocks =
      (64 + Params::K * Params::w1_bytes + 136) / 136;

 public:
  static std::unique_ptr<Circuit<Field>> make_circuit(const Field& f) {
    QuadCircuit<Field> Q(f);
    const CompilerBackend<Field> cbk(&Q);
    const LogicCircuit LC(&cbk, f);
    VerifyCircuit verify(LC);

    auto pk = std::make_unique<typename VerifyCircuit::Pk>();
    pk->input(LC);

    Q.private_input();
    auto sig = std::make_unique<typename VerifyCircuit::SignatureW>();
    sig->input(LC);

    auto w = std::make_unique<typename VerifyCircuit::Witness>();
    w->c_prime_tilde_bws_.resize(kCPrimeTildeBlocks);
    w->input(LC);

    std::array<typename LogicCircuit::v8, 64> mu;
    for (size_t i = 0; i < 64; ++i) mu[i] = LC.template vinput<8>();

    // Every input is in Fq, the subfield of the proof field: its Ligero rows
    // take subfield randomness and their opened elements are sent in 4 bytes.
    Q.begin_full_field();

    verify.assert_valid_signature_on_mu(*pk, *sig, mu, *w);
    return Q.mkcircuit(/*nc=*/1);
  }

  MlDsaZkHarness(std::vector<uint8_t> pkey, std::vector<uint8_t> sig,
                 std::vector<uint8_t> msg, std::vector<uint8_t> ctx)
      : pkey_(std::move(pkey)),
        sig_(std::move(sig)),
        msg_(std::move(msg)),
        ctx_(std::move(ctx)) {}

  // Witness computation from the encoded key, signature and message, then
  // commit and prove. compute_witness appends to its block witnesses, so each
  // proof starts from a fresh witness.
  bool Prove() {
    witness_ = std::make_unique<ml_dsa_witness<Params>>();
    check(witness_->compute_witness(pkey_, sig_, msg_, ctx_),
          "ML-DSA witness computation failed");
    Dense<Field> w(1, circuit_->ninputs);
    DenseFiller<Field> filler(w);
    filler.push_back(f_.one());
    witness_->fill_witness(filler, f_);
    for (uint8_t b : witness_->mu_) filler.push_back(b, 8, f_);
    check(filler.size() == circuit_->ninputs,
          "input count does not match the circuit");

    zkpr_ = std::make_unique<ZkProof<Field>>(*circuit_, kRate, kQueries);
    ZkProver<Field, RSFactory> prover(*circuit_, f_, rs_.factory);
    Transcript tp((uint8_t*)"test", 4);
    prover.commit(*zkpr_, w, tp, rng_);
    return prover.prove(*zkpr_, w, tp);
  }

  // The verifier knows only the public key and receives the serialized
  // proof. With `tamper`, the first public key coefficient is changed, and
  // verification must fail.
  bool Verify(bool tamper = false) const {
    std::vector<uint8_t> bytes;
    zkpr_->write(bytes, f_);
    ZkProof<Field> proof(*circuit_, kRate, kQueries);
    ReadBuffer rb(bytes);
    if (!proof.read(rb, f_)) return false;

    Dense<Field> pub(1, circuit_->npub_in);
    DenseFiller<Field> filler(pub);
    filler.push_back(f_.one());
    witness_->fill_pk(filler, f_);
    if (tamper) f_.add(pub.v_[1], f_.one());

    ZkVerifier<Field, RSFactory> verifier(*circuit_, rs_.factory, kRate,
                                           kQueries, f_);
    Transcript tv((uint8_t*)"test", 4);
    verifier.recv_commitment(proof, tv);
    return verifier.verify(proof, pub, tv);
  }

  // Soundness bits of the proof (zk/zk_soundness.h).
  ZkSoundness Soundness() const {
    const ZkProof<Field> proof(*circuit_, kRate, kQueries);
    return zk_soundness(*circuit_, proof.param,
                        Z::kDegree * std::log2(double(ml_dsa::Fq().m_)));
  }

  // Size of the serialized proof of the last Prove().
  size_t ProofBytes() const {
    std::vector<uint8_t> buf;
    zkpr_->write(buf, f_);
    return buf.size();
  }

 private:
  const Field f_{ml_dsa::Fq(), kBeta};
  const MlDsaRs<Field> rs_{ml_dsa::Fq()};
  const std::unique_ptr<Circuit<Field>> circuit_ = make_circuit(f_);
  const std::vector<uint8_t> pkey_, sig_, msg_, ctx_;
  SecureRandomEngine rng_;
  std::unique_ptr<ZkProof<Field>> zkpr_;
  std::unique_ptr<ml_dsa_witness<Params>> witness_;
};

inline int64_t SteadyNsSince(const std::chrono::steady_clock::time_point& t0) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now() - t0)
      .count();
}

// Body of BM_MLDSA*ZK_Combined.
template <typename Harness>
void RunMlDsaZkBenchmark(benchmark::State& state, Harness& h) {
  for (auto _ : state) {
    const auto t_prove0 = std::chrono::steady_clock::now();
    const bool proved = h.Prove();
    const int64_t prove_ns = SteadyNsSince(t_prove0);
    check(proved, "ML-DSA proof failed");

    const auto t_verify0 = std::chrono::steady_clock::now();
    const bool verified = h.Verify();
    const int64_t verify_ns = SteadyNsSince(t_verify0);
    check(verified, "ML-DSA proof did not verify");

    state.counters["prove_ns"] = static_cast<double>(prove_ns);
    state.counters["verify_ns"] = static_cast<double>(verify_ns);
    state.counters["proof_bytes"] = static_cast<double>(h.ProofBytes());
  }
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_ZK_HARNESS_H_
