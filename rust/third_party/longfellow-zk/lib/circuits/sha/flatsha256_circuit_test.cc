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

#include "circuits/sha/flatsha256_circuit.h"

// This test instantiates flatsha using p256 with the advanced plucker to
// test correctness.

#include <stddef.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_io.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/sha/sha256_test_values.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/testing.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = Fp256Base;

constexpr const Field& F = p256_base;
constexpr size_t kZKRate = 7;
constexpr size_t kZKQueries = 132;  // 109+ bits of security

// =============================================================================
// Evaluation tests verify the correctness of circuit construction by
// comparing the output of the circuit against the reference implementation.
// These tests use an evaluation backend with the P256 field.
// =============================================================================

// Evaluation tests verify the correctness of circuit construction by
// comparing the output of the circuit against the reference implementation.

// Test the circuit via evaluation and comparison against reference.
TEST(FlatSHA256_Circuit, p256_assert_block) {
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  using v32 = typename Logic::v32;
  using FlatSha = FlatSHA256Circuit<Logic, BitPlucker<Logic, kShaPluckerSize>>;
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const FlatSha FSHA(L);
  uint32_t in[16];
  uint32_t H0[8], outw[48], oute[64], outa[64], H1[8];

  for (size_t t = 0; t < sizeof(kSha_bt_) / sizeof(kSha_bt_[0]); ++t) {
    for (size_t i = 0; i < 16; ++i) {
      in[i] = kSha_bt_[t].input[i];
    }
    for (size_t i = 0; i < 8; ++i) {
      H0[i] = kSha_bt_[t].h[i];
    }

    // Given IN and H0, generate witnesses
    FlatSHA256Witness::transform_and_witness_block(in, H0, outw, oute, outa,
                                                   H1);

    // H1 witness must agree with reference
    for (size_t i = 0; i < 8; ++i) {
      EXPECT_EQ(kSha_bt_[t].want[i], H1[i]);
    }

    std::vector<v32> vin(16);
    for (size_t i = 0; i < 16; ++i) {
      vin[i] = L.vbit32(in[i]);
    }

    std::vector<v32> vH0(8), vH1(8);
    for (size_t i = 0; i < 8; ++i) {
      vH0[i] = L.vbit32(H0[i]);
      vH1[i] = L.vbit32(H1[i]);
    }

    std::vector<v32> voutw(48);
    for (size_t i = 0; i < 48; ++i) {
      voutw[i] = L.vbit32(outw[i]);
    }

    std::vector<v32> voute(64), vouta(64);
    for (size_t i = 0; i < 64; ++i) {
      voute[i] = L.vbit32(oute[i]);
      vouta[i] = L.vbit32(outa[i]);
    }

    FSHA.assert_transform_block(vin.data(), vH0.data(), voutw.data(),
                                voute.data(), vouta.data(), vH1.data());
  }
}

// Test the circuit via evaluation and comparison against reference.
TEST(FlatSHA256_Circuit, assert_block_packed) {
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  using v32 = typename Logic::v32;
  using FlatSha = FlatSHA256Circuit<Logic, BitPlucker<Logic, kShaPluckerSize>>;
  using packed_v32 = FlatSha::packed_v32;
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const FlatSha FSHA(L);
  uint32_t in[16];
  uint32_t H0[8], outw[48], oute[64], outa[64], H1[8];

  for (size_t i = 0; i < 16; ++i) {
    in[i] = kSha_bt_[0].input[i];
  }
  for (size_t i = 0; i < 8; ++i) {
    H0[i] = kSha_bt_[0].h[i];
  }

  // Given IN and H0, generate witnesses
  FlatSHA256Witness::transform_and_witness_block(in, H0, outw, oute, outa, H1);

  // H1 witness must agree with reference
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(kSha_bt_[0].want[i], H1[i]);
  }

  std::vector<v32> vin(16);
  for (size_t i = 0; i < 16; ++i) {
    vin[i] = L.vbit32(in[i]);
  }

  std::vector<packed_v32> vH0(8), vH1(8);
  BitPluckerEncoder<Field, kShaPluckerSize> BPENC(F);
  for (size_t i = 0; i < 8; ++i) {
    vH0[i] = L.konst(BPENC.mkpacked_v32(H0[i]));
    vH1[i] = L.konst(BPENC.mkpacked_v32(H1[i]));
  }

  std::vector<packed_v32> voutw(48);
  for (size_t i = 0; i < 48; ++i) {
    voutw[i] = L.konst(BPENC.mkpacked_v32(outw[i]));
  }

  std::vector<packed_v32> voute(64), vouta(64);
  for (size_t i = 0; i < 64; ++i) {
    voute[i] = L.konst(BPENC.mkpacked_v32(oute[i]));
    vouta[i] = L.konst(BPENC.mkpacked_v32(outa[i]));
  }

  FSHA.assert_transform_block(vin.data(), vH0.data(), voutw.data(),
                              voute.data(), vouta.data(), vH1.data());
}

// Test the circuit via evaluation and comparison against reference.
TEST(FlatSHA256_Circuit, assert_message) {
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  using v8 = typename Logic::v8;
  using v256 = typename Logic::v256;
  using FlatSha = FlatSHA256Circuit<Logic, BitPlucker<Logic, kShaPluckerSize>>;
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const FlatSha FSHA(L);
  BitPluckerEncoder<Field, kShaPluckerSize> BPENC(F);

  constexpr size_t max = 32;
  std::vector<uint8_t> in(64 * max);
  std::vector<FlatSHA256Witness::BlockWitness> bw(max);

  std::vector<v8> inW(64 * max);
  std::vector<FlatSha::BlockWitness> bwW(max);

  for (size_t i = 0; i < sizeof(SHA256_TV) / sizeof(SHA256_TV[0]); ++i) {
    size_t len = SHA256_TV[i].len;
    if (len + 9 < 64 * max) {
      continue;
    }

    uint8_t numb;
    FlatSHA256Witness::transform_and_witness_message(
        len, (const uint8_t*)SHA256_TV[i].str, max, numb, in.data(), bw.data());

    // The last H1 must agree with the expected output
    for (size_t j = 0; j < 8; ++j) {
      uint32_t h1j = SHA256_ru32be(&SHA256_TV[i].hash[j * 4]);
      EXPECT_EQ(bw[numb - 1].h1[j], h1j);
    }

    v256 target;
    for (size_t j = 0; j < 256; ++j) {
      target[j] = L.bit((SHA256_TV[i].hash[(255 - j) / 8] >> (j % 8)) & 0x1);
    }

    // fill input wires
    v8 numbW = L.vbit8(numb);

    for (size_t j = 0; j < max * 64; j++) {
      inW[j] = L.vbit8(in[j]);
    }

    for (size_t j = 0; j < max; j++) {
      for (size_t k = 0; k < 48; ++k) {
        bwW[j].outw[k] = L.konst(BPENC.mkpacked_v32(bw[j].outw[k]));
      }
      for (size_t k = 0; k < 64; ++k) {
        bwW[j].oute[k] = L.konst(BPENC.mkpacked_v32(bw[j].oute[k]));
        bwW[j].outa[k] = L.konst(BPENC.mkpacked_v32(bw[j].outa[k]));
      }

      for (size_t k = 0; k < 8; ++k) {
        bwW[j].h1[k] = L.konst(BPENC.mkpacked_v32(bw[j].h1[k]));
      }
    }

    FSHA.assert_message_hash(max, numbW, inW.data(), target, bwW.data());
  }
}

// =============================================================================
// Compiler tests are used to assess the circuit size and verify that the
// circuit works in sumcheck or zk proof processes. These tests use different
// fields.
// =============================================================================

template <class Field, size_t plucker_size>
std::unique_ptr<Circuit<Field>> test_block_circuit_size(const Field& f,
                                                        const char* test_name) {
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;
  using v32C = typename LogicCircuit::v32;
  using FlatShaC =
      FlatSHA256Circuit<LogicCircuit, BitPlucker<LogicCircuit, plucker_size>>;
  using packed_v32C = typename FlatShaC::packed_v32;

  QuadCircuit<Field> Q(f);
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, f);
  FlatShaC FSHAC(LC);

  std::vector<v32C> vin(16);
  for (size_t i = 0; i < 16; ++i) {
    vin[i] = LC.template vinput<32>();
  }

  if (plucker_size == 1) {
    std::vector<v32C> vH0(8), vH1(8), voutw(48), voute(64), vouta(64);
    for (size_t i = 0; i < 8; ++i) {
      vH0[i] = LC.template vinput<32>();
      vH1[i] = LC.template vinput<32>();
    }
    for (size_t i = 0; i < 48; ++i) {
      voutw[i] = LC.template vinput<32>();
    }
    for (size_t i = 0; i < 64; ++i) {
      voute[i] = LC.template vinput<32>();
      vouta[i] = LC.template vinput<32>();
    }
    FSHAC.assert_transform_block(vin.data(), vH0.data(), voutw.data(),
                                 voute.data(), vouta.data(), vH1.data());
  } else {
    std::vector<packed_v32C> vH0(8), vH1(8), voutw(48), voute(64), vouta(64);
    for (size_t i = 0; i < 8; ++i) {
      vH0[i] = FlatShaC::packed_input(LC);
      vH1[i] = FlatShaC::packed_input(LC);
    }
    for (size_t i = 0; i < 48; ++i) {
      voutw[i] = FlatShaC::packed_input(LC);
    }
    for (size_t i = 0; i < 64; ++i) {
      voute[i] = FlatShaC::packed_input(LC);
      vouta[i] = FlatShaC::packed_input(LC);
    }
    FSHAC.assert_transform_block(vin.data(), vH0.data(), voutw.data(),
                                 voute.data(), vouta.data(), vH1.data());
  }

  auto CIRCUIT = Q.mkcircuit(1);
  dump_info(test_name, Q);

  ZkProof<Field> zkpr(*CIRCUIT, kZKRate, kZKQueries);
  log(INFO, "SHA: nw:%zd nq:%zd r:%zd w:%zd bl:%zd bl_enc:%zd nrow:%zd\n",
      zkpr.param.nw, zkpr.param.nq, zkpr.param.r, zkpr.param.w,
      zkpr.param.block, zkpr.param.block_enc, zkpr.param.nrow);

  return CIRCUIT;
}

TEST(FlatSHA256_Circuit, block_size_p256) {
  test_block_circuit_size<Fp256Base, 1>(p256_base, "block_size_p256_pack_1");
}

TEST(FlatSHA256_Circuit, block_size_p256_2) {
  test_block_circuit_size<Fp256Base, 2>(p256_base, "block_size_p256_pack_2");
}

TEST(FlatSHA256_Circuit, block_size_p256_3) {
  test_block_circuit_size<Fp256Base, 3>(p256_base, "block_size_p256_pack_3");
}

TEST(FlatSHA256_Circuit, block_size_p256_4) {
  test_block_circuit_size<Fp256Base, 4>(p256_base, "block_size_p256_pack_4");
}

TEST(FlatSHA256_Circuit, block_size_gf2_128_1) {
  using f_128 = GF2_128<>;
  const f_128 Fs;
  test_block_circuit_size<f_128, 1>(Fs, "block_size_gf2128_pack_1");
}

TEST(FlatSHA256_Circuit, block_size_gf2_128_2) {
  using f_128 = GF2_128<>;
  const f_128 Fs;
  test_block_circuit_size<f_128, 2>(Fs, "block_size_gf2128_pack_2");
}

TEST(FlatSHA256_Circuit, block_size_gf2_128_3) {
  using f_128 = GF2_128<>;
  const f_128 Fs;
  test_block_circuit_size<f_128, 3>(Fs, "block_size_gf2128_pack_3");
}

TEST(FlatSHA256_Circuit, block_size_gf2_128_4) {
  using f_128 = GF2_128<>;
  const f_128 Fs;
  test_block_circuit_size<f_128, 4>(Fs, "block_size_gf2128_pack_4");
}

}  // namespace

namespace bench {
// =============================================================================
// Benchmarks for sumcheck- and zk- proofs about hashing messages of various
// sizes over different fields.
// =============================================================================

template <class Field, size_t pluckerSize>
std::unique_ptr<Circuit<Field>> make_circuit(size_t numBlocks, size_t numCopies,
                                             const Field& f) {
  set_log_level(ERROR);
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using FlatShaC =
      FlatSHA256Circuit<LogicCircuit, BitPlucker<LogicCircuit, pluckerSize>>;
  using ShaBlockWitness = typename FlatShaC::BlockWitness;

  QuadCircuit<Field> Q(f);
  const CompilerBackend cbk(&Q);
  const LogicCircuit lc(&cbk, f);
  FlatShaC sha(lc);

  v8 nb = lc.template vinput<8>();
  std::vector<v8> in(64 * numBlocks);
  for (size_t i = 0; i < 64 * numBlocks; ++i) {
    in[i] = lc.template vinput<8>();
  }

  v256 target = lc.template vinput<256>();

  std::vector<ShaBlockWitness> bw(numBlocks);
  for (size_t j = 0; j < numBlocks; j++) {
    bw[j].input(lc);
  }

  sha.assert_message_hash(numBlocks, nb, &in[0], target, &bw[0]);

  auto circuit = Q.mkcircuit(numCopies);
  dump_info("assert_message_hash", Q);
  return circuit;
}

template <class Field, size_t N>
void push(const std::array<typename Field::Elt, N>& a, size_t& wi, size_t c,
          size_t numCopies, Dense<Field>& W) {
  for (size_t i = 0; i < N; ++i) {
    W.v_[(wi++) * numCopies + c] = a[i];
  }
}

template <class Field>
void push(uint8_t a, size_t& wi, size_t c, size_t numCopies, Dense<Field>& W,
          const Field& f) {
  for (size_t i = 0; i < 8; ++i) {
    W.v_[(wi++) * numCopies + c] = (a >> i) & 1 ? f.one() : f.zero();
  }
}

// Copy the same input for all copies.
template <class Field, size_t pluckerSize>
void fill_input(Dense<Field>& W, size_t numBlocks, size_t ninputs,
                size_t numCopies, const Field& f) {
  uint8_t numb;
  std::vector<uint8_t> inb(64 * numBlocks);
  std::vector<FlatSHA256Witness::BlockWitness> bwb(numBlocks);
  size_t bmax = sizeof(kSha_benchmark_)/sizeof(kSha_benchmark_[0]);
  size_t bench_index = numBlocks - 1;
  if (bench_index > bmax) {
    bench_index = bmax - 1;
  }
  std::vector<uint8_t> message(kSha_benchmark_[bench_index].len, 'a');
  FlatSHA256Witness::transform_and_witness_message(
      message.size(), message.data(), numBlocks, numb, &inb[0], &bwb[0]);

  const uint8_t *hash = kSha_benchmark_[bench_index].hash;

  // fill input wires
  for (size_t c = 0; c < numCopies; ++c) {
    size_t wi = 0;

    W.v_[(wi++) * numCopies + c] = f.one();
    push(numb, wi, c, numCopies, W, f);
    for (size_t j = 0; j < numBlocks * 64; j++) {
      push(inb[j], wi, c, numCopies, W, f);
    }

    // Target hash.
    for (size_t j = 0; j < 256; ++j) {
      W.v_[(wi++) * numCopies + c] =
          (hash[(255 - j) / 8] >> (j % 8)) & 1 ? f.one() : f.zero();
    }

    // Sha block witnesses.
    BitPluckerEncoder<Field, pluckerSize> BPENC(f);
    for (size_t j = 0; j < numBlocks; j++) {
      for (size_t k = 0; k < 48; ++k) {
        push(BPENC.mkpacked_v32(bwb[j].outw[k]), wi, c, numCopies, W);
      }
      for (size_t k = 0; k < 64; ++k) {
        push(BPENC.mkpacked_v32(bwb[j].oute[k]), wi, c, numCopies, W);
        push(BPENC.mkpacked_v32(bwb[j].outa[k]), wi, c, numCopies, W);
      }
      for (size_t k = 0; k < 8; ++k) {
        push(BPENC.mkpacked_v32(bwb[j].h1[k]), wi, c, numCopies, W);
      }
    }
  }
}

void BM_ShaSumcheckProver_fp2_128(benchmark::State& state) {
  using f_128 = GF2_128<>;
  const f_128 Fs;

  size_t numBlocks = state.range(0);
  std::unique_ptr<Circuit<f_128>> CIRCUIT =
      make_circuit<f_128, 2>(numBlocks, 1, Fs);

  auto W = Dense<f_128>(1, CIRCUIT->ninputs);

  fill_input<f_128, 2>(W, numBlocks, CIRCUIT->ninputs, 1, Fs);

  // Run benchmark
  for (auto s : state) {
    Proof<f_128> proof(CIRCUIT->nl);
    run_prover(CIRCUIT.get(), W.clone(), &proof, Fs);
    benchmark::DoNotOptimize(proof);
  }
}
BENCHMARK(BM_ShaSumcheckProver_fp2_128)->RangeMultiplier(2)->Range(1, 33);

void BM_ShaSumcheckCopyProver_fp2_128(benchmark::State& state) {
  using f_128 = GF2_128<>;
  const f_128 F;
  size_t numCopies = state.range(0);
  std::unique_ptr<Circuit<f_128>> CIRCUIT =
      make_circuit<f_128, 2>(1, numCopies, F);

  auto W = Dense<f_128>(numCopies, CIRCUIT->ninputs);
  fill_input<f_128, 2>(W, 1, CIRCUIT->ninputs, numCopies, F);

  for (auto s : state) {
    Proof<f_128> proof(CIRCUIT->nl);
    run_prover(CIRCUIT.get(), W.clone(), &proof, F);
    benchmark::DoNotOptimize(proof);
  }
}

BENCHMARK(BM_ShaSumcheckCopyProver_fp2_128)->RangeMultiplier(2)->Range(1, 33);

void BM_ShaZK_fp2_128(benchmark::State& state) {
  using f_128 = GF2_128<>;
  const f_128 Fs;
  using RSFactory = LCH14ReedSolomonFactory<f_128>;

  const size_t numBlocks = state.range(0);
  constexpr size_t kPluckerSize = 2;
  std::unique_ptr<Circuit<f_128>> CIRCUIT =
      make_circuit<f_128, kPluckerSize>(numBlocks, 1, Fs);

  auto W = Dense<f_128>(1, CIRCUIT->ninputs);

  fill_input<f_128, kPluckerSize>(W, numBlocks, CIRCUIT->ninputs, 1, Fs);

  const RSFactory rsf(Fs);
  Transcript tp((uint8_t*)"test", 4);
  SecureRandomEngine rng;

  for (auto s : state) {
    ZkProof<f_128> zkpr(*CIRCUIT, kZKRate, kZKQueries);
    ZkProver<f_128, RSFactory> prover(*CIRCUIT, Fs, rsf);
    prover.commit(zkpr, W, tp, rng);
    prover.prove(zkpr, W, tp);
    benchmark::DoNotOptimize(zkpr);
  }
}
BENCHMARK(BM_ShaZK_fp2_128)->RangeMultiplier(2)->Range(1, 33);

void BM_ShaZK_Fp64_2(benchmark::State& state) {
  using f_goldi = Fp<1>;
  using Field2 = Fp2<f_goldi>;
  using Elt2 = typename Field2::Elt;
  using FftConvolutionFactory = FFTConvolutionFactory<Field2>;
  using RSFactory = ReedSolomonFactory<Field2, FftConvolutionFactory>;

  const size_t numBlocks = state.range(0);
  constexpr size_t kPluckerSize = 3;
  const Fp<1> F("18446744069414584321");
  const Field2 base_2(F);

  std::unique_ptr<Circuit<Field2>> CIRCUIT =
      make_circuit<Field2, kPluckerSize>(numBlocks, 1, base_2);

  auto W = Dense<Field2>(1, CIRCUIT->ninputs);

  fill_input<Field2, kPluckerSize>(W, numBlocks, CIRCUIT->ninputs, 1, base_2);

  static constexpr char kSmallRoot[] = "2752994695033296049";
  static constexpr uint64_t kSmallOrder = 1ull << 32;

  const Elt2 omega = base_2.of_string(kSmallRoot);
  const FftConvolutionFactory fft(base_2, omega, kSmallOrder);
  const RSFactory rsf(fft, base_2);

  Transcript tp((uint8_t*)"test", 4);
  SecureRandomEngine rng;

  for (auto s : state) {
    ZkProof<Field2> zkpr(*CIRCUIT, kZKRate, kZKQueries);
    ZkProver<Field2, RSFactory> prover(*CIRCUIT, base_2, rsf);
    prover.commit(zkpr, W, tp, rng);
    prover.prove(zkpr, W, tp);
    benchmark::DoNotOptimize(zkpr);
  }
}
BENCHMARK(BM_ShaZK_Fp64_2)->RangeMultiplier(2)->Range(1, 32);

// This benchmark measures the time it takes to bind the quad for SHA.
void BM_ShaZK_quadbind_fp2_128(benchmark::State& state) {
  using f_128 = GF2_128<>;
  using Elt = f_128::Elt;
  const f_128 Fs;

  const size_t numBlocks = state.range(0);
  constexpr size_t kPluckerSize = 2;
  std::unique_ptr<Circuit<f_128>> CIRCUIT =
      make_circuit<f_128, kPluckerSize>(numBlocks, 1, Fs);

  SecureRandomEngine rng;

  Elt alpha = rng.elt(Fs);
  Elt beta = rng.elt(Fs);
  Elt g0[64], g1[64];
  for (size_t i = 0; i < 64; ++i) {
    g0[i] = rng.elt(Fs);
    g1[i] = rng.elt(Fs);
  }

  for (auto s : state) {
    size_t logv = CIRCUIT->logv;
    for (size_t ly = 0; ly < CIRCUIT->nl; ++ly) {
      auto HQUAD = CIRCUIT->l[ly].quad->bind_g(logv, g0, g1, alpha, beta, Fs);
      logv = CIRCUIT->l[ly].logw;
    }
  }
}
BENCHMARK(BM_ShaZK_quadbind_fp2_128)->RangeMultiplier(2)->Range(1, 32);

}  // namespace bench
}  // namespace proofs
