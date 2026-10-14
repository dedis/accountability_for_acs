// SHAKE256 counterpart of BM_ShaZK_fp2_128 in
// circuits/sha/flatsha256_circuit_test.cc: for each n, it proves the hash of
// the same message (64n - 14 bytes of 'a') with a 32-byte output, over the
// same field, Reed-Solomon factory, Ligero parameters and timed region.

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <vector>

#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/panic.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_testing.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

constexpr size_t kShakeRate = 136;
constexpr size_t kDigestBytes = 32;

// Message length of BM_ShaZK_fp2_128 for numBlocks SHA-256 blocks
// (kSha_benchmark_ in circuits/sha/sha256_test_values.h).
size_t sha_bench_message_len(size_t numBlocks) { return 64 * numBlocks - 14; }

// Keccak-f calls for a message of len bytes and a 32-byte output.
size_t keccak_blocks(size_t len) { return (len + kShakeRate) / kShakeRate; }

template <class Field>
std::unique_ptr<Circuit<Field>> make_shake256_circuit(size_t len,
                                                      const Field& f) {
  QuadCircuit<Field> Q(f);
  using CompilerBackend = proofs::CompilerBackend<Field>;
  using LogicCircuit = proofs::Logic<Field, CompilerBackend>;
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, f);
  Sha3Circuit<LogicCircuit> SHAC(LC);

  std::vector<typename LogicCircuit::v8> seed(len);
  for (size_t i = 0; i < len; ++i) seed[i] = LC.template vinput<8>();

  std::vector<typename LogicCircuit::v8> want(kDigestBytes);
  for (size_t i = 0; i < kDigestBytes; ++i) want[i] = LC.template vinput<8>();

  std::vector<typename Sha3Circuit<LogicCircuit>::BlockWitness> bws(
      keccak_blocks(len));
  for (auto& bw : bws) bw.input(LC);

  std::vector<typename LogicCircuit::v8> out;
  SHAC.assert_shake256(seed, kDigestBytes, out, bws);
  for (size_t i = 0; i < kDigestBytes; ++i) LC.vassert_eq(want[i], out[i]);

  return Q.mkcircuit(/*nc=*/1);
}

// Fills all inputs: the constant one, the message, the digest and the
// Keccak block witnesses. Returns the digest.
template <class Field>
std::vector<uint8_t> fill_input(Dense<Field>& W,
                                const std::vector<uint8_t>& message,
                                const Field& f) {
  std::vector<Sha3Witness::BlockWitness> bws;
  Sha3Witness::compute_witness_shake256(message, kDigestBytes, bws);
  check(bws.size() == keccak_blocks(message.size()),
        "unexpected number of Keccak blocks");

  // The last witness holds the final state, whose first 32 bytes
  // (little-endian lanes) are the digest.
  std::vector<uint8_t> digest(kDigestBytes);
  for (size_t i = 0; i < kDigestBytes; ++i) {
    const size_t lane = i / 8;
    digest[i] = static_cast<uint8_t>(
        bws.back().a_intermediate[23][lane % 5][lane / 5] >> (8 * (i % 8)));
  }

  DenseFiller<Field> filler(W);
  filler.push_back(f.one());
  for (uint8_t b : message) filler.push_back(b, 8, f);
  for (uint8_t b : digest) filler.push_back(b, 8, f);
  Sha3Witness::fill_witness(filler, bws, f);
  check(filler.size() == W.n1_, "input count does not match the circuit");
  return digest;
}

// The digest matches the reference implementation and the proof verifies,
// for messages of one, two and 16 Keccak blocks (n = 1, 3, 33).
TEST(Shake256ZK, ProvesTheBenchmarkMessages) {
  using f_128 = GF2_128<>;
  const f_128 Fs;
  using RSFactory = LCH14ReedSolomonFactory<f_128>;
  const RSFactory rsf(Fs);
  set_log_level(ERROR);

  for (size_t numBlocks : {1, 3, 33}) {
    const std::vector<uint8_t> message(sha_bench_message_len(numBlocks), 'a');
    auto CIRCUIT = make_shake256_circuit<f_128>(message.size(), Fs);
    auto W = Dense<f_128>(1, CIRCUIT->ninputs);
    const std::vector<uint8_t> digest = fill_input<f_128>(W, message, Fs);

    std::vector<uint8_t> want(kDigestBytes);
    Sha3Reference::shake256Hash(message.data(), message.size(), want.data(),
                                kDigestBytes);
    EXPECT_EQ(digest, want) << "numBlocks=" << numBlocks;

    ZkProof<f_128> zkpr(*CIRCUIT, kLigeroRate, kLigeroNreq);
    ZkProver<f_128, RSFactory> prover(*CIRCUIT, Fs, rsf);
    Transcript tp((uint8_t*)"test", 4);
    SecureRandomEngine rng;
    prover.commit(zkpr, W, tp, rng);
    ASSERT_TRUE(prover.prove(zkpr, W, tp)) << "numBlocks=" << numBlocks;

    ZkVerifier<f_128, RSFactory> verifier(*CIRCUIT, rsf, kLigeroRate,
                                          kLigeroNreq, Fs);
    Transcript tv((uint8_t*)"test", 4);
    verifier.recv_commitment(zkpr, tv);
    Dense<f_128> pub(1, 0);
    EXPECT_TRUE(verifier.verify(zkpr, pub, tv)) << "numBlocks=" << numBlocks;
  }
}

void BM_ShakeZK_fp2_128(benchmark::State& state) {
  using f_128 = GF2_128<>;
  const f_128 Fs;
  using RSFactory = LCH14ReedSolomonFactory<f_128>;
  set_log_level(ERROR);

  const size_t numBlocks = state.range(0);
  const std::vector<uint8_t> message(sha_bench_message_len(numBlocks), 'a');
  std::unique_ptr<Circuit<f_128>> CIRCUIT =
      make_shake256_circuit<f_128>(message.size(), Fs);

  auto W = Dense<f_128>(1, CIRCUIT->ninputs);
  fill_input<f_128>(W, message, Fs);

  const RSFactory rsf(Fs);
  Transcript tp((uint8_t*)"test", 4);
  SecureRandomEngine rng;

  for (auto s : state) {
    ZkProof<f_128> zkpr(*CIRCUIT, kLigeroRate, kLigeroNreq);
    ZkProver<f_128, RSFactory> prover(*CIRCUIT, Fs, rsf);
    prover.commit(zkpr, W, tp, rng);
    prover.prove(zkpr, W, tp);
    benchmark::DoNotOptimize(zkpr);
  }
  state.counters["message_bytes"] = message.size();
  state.counters["keccak_blocks"] = keccak_blocks(message.size());
}
BENCHMARK(BM_ShakeZK_fp2_128)->RangeMultiplier(2)->Range(1, 33);

}  // namespace
}  // namespace proofs
