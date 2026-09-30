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

#include "circuits/tests/ec/attr_commitment_experiment_shared.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>

#include <openssl/sha.h>

#include "algebra/convolution.h"
#include "algebra/fp.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace {

using Field = Fp256Base;
using Field2 = Fp2<Fp256Base>;
using ConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, Field2>;
using RSFactory = ReedSolomonFactory<Fp256Base, ConvolutionFactory>;
using LogicCircuit = Logic<Field, CompilerBackend<Field>>;
using EltW = LogicCircuit::EltW;
using v8 = LogicCircuit::v8;
using v256 = LogicCircuit::v256;

constexpr size_t kRate = 7;
constexpr size_t kQueries = 132;
constexpr size_t kAttrBytes = 32;
constexpr size_t kShaPluckerBits = 3;

// Root of unity for the f_p256^2 extension field (same as credential benchmark).
static constexpr char kP256ExtRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
static constexpr char kP256ExtRootY[] =
    "840879943585409076957404614278186605601821689971823787493130182544504602"
    "12908";
constexpr uint64_t kP256ExtRootOrder = 1ull << 31;

static void sha256_bytes(const uint8_t* msg, size_t len, uint8_t out[32]) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, msg, len);
  SHA256_Final(out, &ctx);
}

template <size_t N>
static void random_bytes(SecureRandomEngine& rng, std::array<uint8_t, N>& out) {
  rng.bytes(out.data(), N);
}

static constexpr size_t blocks_for_msg_bytes(size_t msg_bytes) {
  return (msg_bytes + 1 + 8 + 63) / 64;
}

template <size_t NumBlocks>
static void sha256_message_witness(
    const uint8_t* msg, size_t msg_bytes,
    std::array<uint8_t, 64 * NumBlocks>& in,
    std::array<FlatSHA256Witness::BlockWitness, NumBlocks>& bw) {
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(msg_bytes, msg, NumBlocks, numb,
                                                   in.data(), bw.data());
  check(numb == NumBlocks, "sha witness: unexpected block count");
}

// =============================================================================
// Flat SHA commitment circuit:
//   public: digest bits (v256)
//   witness: padded message bytes + sha block witnesses
// =============================================================================

template <size_t NAttrs>
struct FlatCtx {
  static constexpr size_t kMsgBytes = NAttrs * kAttrBytes;
  static constexpr size_t kBlocks = blocks_for_msg_bytes(kMsgBytes);
  std::array<std::array<uint8_t, 32>, NAttrs> attrs{};
  std::array<uint8_t, 32> digest{};
  std::array<uint8_t, 64 * kBlocks> sha_in{};
  std::array<FlatSHA256Witness::BlockWitness, kBlocks> sha_bw{};
};

template <size_t NAttrs>
std::unique_ptr<Circuit<Field>> make_flat_circuit() {
  using FlatSha =
      FlatSHA256Circuit<LogicCircuit, BitPlucker<LogicCircuit, kShaPluckerBits>>;
  QuadCircuit<Field> Q(p256_base);
  const CompilerBackend<Field> cbk(&Q);
  const LogicCircuit lc(&cbk, p256_base);
  FlatSha sha(lc);

  // Public: digest bits (same interface as flatsha256_circuit_test bench).
  v256 digest_pub = lc.template vinput<256>();

  Q.private_input();

  // Private: nb (number of blocks), padded message bytes, and SHA witnesses.
  v8 nb = lc.template vinput<8>();
  std::array<v8, 64 * FlatCtx<NAttrs>::kBlocks> msg_in{};
  for (auto& b : msg_in) b = lc.template vinput<8>();
  std::array<typename FlatSha::BlockWitness, FlatCtx<NAttrs>::kBlocks> bw{};
  for (auto& w : bw) w.input(lc);

  sha.assert_message_hash(FlatCtx<NAttrs>::kBlocks, nb, msg_in.data(), digest_pub,
                          bw.data());

  return Q.mkcircuit(1);
}

template <size_t NAttrs>
static void fill_flat(Dense<Field>& W, const FlatCtx<NAttrs>& ctx, bool prover) {
  DenseFiller<Field> f(W);

  // Wire 0 is the compiler's implicit constant-1 input (see QuadCircuit ctor).
  f.push_back(p256_base.one());

  // Public: digest bits, same mapping as flatsha256_circuit_test.cc
  for (size_t j = 0; j < 256; ++j) {
    const uint8_t byte = ctx.digest[(255 - j) / 8];
    const uint8_t bit = (byte >> (j % 8)) & 1;
    f.push_back(bit ? p256_base.one() : p256_base.zero());
  }

  if (!prover) return;

  // Private: nb, padded message bytes, witness.
  f.push_back(static_cast<uint8_t>(FlatCtx<NAttrs>::kBlocks), 8, p256_base);
  for (size_t i = 0; i < 64 * FlatCtx<NAttrs>::kBlocks; ++i) {
    f.push_back(ctx.sha_in[i], 8, p256_base);
  }

  BitPluckerEncoder<Field, kShaPluckerBits> enc(p256_base);
  for (size_t b = 0; b < FlatCtx<NAttrs>::kBlocks; ++b) {
    for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(ctx.sha_bw[b].outw[k]));
    for (size_t k = 0; k < 64; ++k) {
      f.push_back(enc.mkpacked_v32(ctx.sha_bw[b].oute[k]));
      f.push_back(enc.mkpacked_v32(ctx.sha_bw[b].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(ctx.sha_bw[b].h1[k]));
  }
  while (f.size() < W.n1_) f.push_back(p256_base.zero());
  check(f.size() == W.n1_, "fill_flat: size mismatch");
}

// =============================================================================
// Merkle circuit:
//   leaf = SHA256(be32(index) || value_bytes)
//   internal = SHA256(left_digest || right_digest)
//   public: root bytes (32)
//   witness: for each of K claims: value bytes + path siblings + path bits + SHA witnesses
// =============================================================================

constexpr size_t kShaBlocks64 = 2;  // SHA256 over 64 bytes => 2 blocks with padding.

template <size_t Depth>
struct ClaimCtx {
  std::array<uint8_t, 32> value_be{};
  std::array<std::array<uint8_t, 32>, Depth> path_elements{};
  std::array<Field::Elt, Depth> path_indices{};  // 0/1 in field
  std::array<FlatSHA256Witness::BlockWitness, 2> leaf_bw{};
  std::array<std::array<FlatSHA256Witness::BlockWitness, 2>, Depth> node_bw{};
};

template <size_t NAttrs, size_t Depth, size_t K>
struct MerkleCtx {
  static_assert((1u << Depth) == NAttrs);
  std::array<std::array<uint8_t, 32>, NAttrs> attrs{};
  std::array<uint8_t, 32> root{};
  std::array<ClaimCtx<Depth>, K> claims{};
};

template <size_t NAttrs, size_t Depth, size_t K>
std::unique_ptr<Circuit<Field>> make_merkle_circuit() {
  using FlatSha =
      FlatSHA256Circuit<LogicCircuit, BitPlucker<LogicCircuit, kShaPluckerBits>>;
  using ShaBW = typename FlatSha::BlockWitness;
  QuadCircuit<Field> Q(p256_base);
  const CompilerBackend<Field> cbk(&Q);
  const LogicCircuit lc(&cbk, p256_base);
  FlatSha sha(lc);

  std::array<v8, 32> root_pub{};
  for (auto& b : root_pub) b = lc.template vinput<8>();

  Q.private_input();

  auto digest_from_bw = [&](const ShaBW bw[2]) {
    std::array<v8, 32> out{};
    for (size_t j = 0; j < 8; ++j) {
      auto hj = sha.bp_.unpack_v32(bw[1].h1[j]);
      for (size_t k = 0; k < 32; ++k) {
        // hj[k] = bit k (LSB-first) of SHA256 word j.
        // In big-endian SHA256, byte (j*4 + b) occupies bits 24-8*b .. 31-8*b
        // of word j, so byte b_within_word = 3 - k/8 (reversed within word).
        const size_t byte_index = (j * 4) + (3 - k / 8);
        const size_t bit_index = (k % 8);
        out[byte_index][bit_index] = hj[k];
      }
    }
    return out;
  };

  auto hash2_64bytes = [&](const std::array<v8, 32>& left,
                           const std::array<v8, 32>& right,
                           const ShaBW bw[2]) {
    v8 in[64 * kShaBlocks64];
    for (size_t i = 0; i < 32; ++i) in[i] = left[i];
    for (size_t i = 0; i < 32; ++i) in[32 + i] = right[i];
    // Padding for 64-byte message: a full extra block.
    in[64] = lc.template vbit<8>(0x80);
    for (size_t i = 65; i < 64 * kShaBlocks64 - 8; ++i) in[i] = lc.template vbit<8>(0x00);
    // length = 512 bits = 0x0000000000000200
    for (size_t i = 0; i < 6; ++i) in[64 * kShaBlocks64 - 8 + i] = lc.template vbit<8>(0x00);
    in[64 * kShaBlocks64 - 2 - 1] = lc.template vbit<8>(0x00);
    in[64 * kShaBlocks64 - 2] = lc.template vbit<8>(0x02);
    in[64 * kShaBlocks64 - 1] = lc.template vbit<8>(0x00);

    const auto nb2 = lc.template vbit<8>(kShaBlocks64);
    sha.assert_message(kShaBlocks64, nb2, in, bw);
    return digest_from_bw(bw);
  };

  auto be32_of_u8 = [&](uint8_t x) {
    std::array<v8, 32> name{};
    for (size_t i = 0; i < 31; ++i) name[i] = lc.template vbit<8>(0x00);
    name[31] = lc.template vbit<8>(x);
    return name;
  };

  for (size_t claim_i = 0; claim_i < K; ++claim_i) {
    v8 value_be[32];
    for (auto& b : value_be) b = lc.template vinput<8>();
    std::array<std::array<v8, 32>, Depth> sib{};
    std::array<EltW, Depth> path_idx{};
    for (size_t d = 0; d < Depth; ++d) {
      for (auto& b : sib[d]) b = lc.template vinput<8>();
      path_idx[d] = lc.eltw_input();
    }
    std::array<ShaBW, 2> leaf_bw{};
    for (auto& w : leaf_bw) w.input(lc);
    std::array<std::array<ShaBW, 2>, Depth> node_bw{};
    for (size_t d = 0; d < Depth; ++d) for (auto& w : node_bw[d]) w.input(lc);

    auto name = be32_of_u8(static_cast<uint8_t>(claim_i));
    std::array<v8, 32> val{};
    for (size_t i = 0; i < 32; ++i) val[i] = value_be[i];

    std::array<v8, 32> cur = hash2_64bytes(name, val, leaf_bw.data());
    for (size_t d = 0; d < Depth; ++d) {
      typename LogicCircuit::BitW bi(path_idx[d], lc.f_);
      lc.assert_is_bit(bi);
      std::array<v8, 32> left{}, right{};
      for (size_t i = 0; i < 32; ++i) {
        lc.vmux(bi, left[i], sib[d][i], cur[i]);
        lc.vmux(bi, right[i], cur[i], sib[d][i]);
      }
      cur = hash2_64bytes(left, right, node_bw[d].data());
    }

    for (size_t i = 0; i < 32; ++i) lc.vassert_eq(cur[i], root_pub[i]);
  }

  return Q.mkcircuit(1);
}

static void push_sha64_bw(DenseFiller<Field>& f,
                          const std::array<FlatSHA256Witness::BlockWitness, 2>& bw) {
  BitPluckerEncoder<Field, kShaPluckerBits> enc(p256_base);
  for (size_t b = 0; b < 2; ++b) {
    for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(bw[b].outw[k]));
    for (size_t k = 0; k < 64; ++k) {
      f.push_back(enc.mkpacked_v32(bw[b].oute[k]));
      f.push_back(enc.mkpacked_v32(bw[b].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(bw[b].h1[k]));
  }
}

template <size_t NAttrs, size_t Depth, size_t K>
static void fill_merkle(Dense<Field>& W, const MerkleCtx<NAttrs, Depth, K>& ctx,
                        bool prover) {
  DenseFiller<Field> f(W);
  f.push_back(p256_base.one());
  for (size_t i = 0; i < 32; ++i) f.push_back(ctx.root[i], 8, p256_base);
  if (!prover) return;
  for (size_t i = 0; i < K; ++i) {
    const auto& c = ctx.claims[i];
    for (size_t j = 0; j < 32; ++j) f.push_back(c.value_be[j], 8, p256_base);
    for (size_t d = 0; d < Depth; ++d) {
      for (size_t j = 0; j < 32; ++j) f.push_back(c.path_elements[d][j], 8, p256_base);
      f.push_back(c.path_indices[d]);
    }
    push_sha64_bw(f, c.leaf_bw);
    for (size_t d = 0; d < Depth; ++d) push_sha64_bw(f, c.node_bw[d]);
  }
  while (f.size() < W.n1_) f.push_back(p256_base.zero());
  check(f.size() == W.n1_, "fill_merkle: size mismatch");
}

}  // namespace

// Define the opaque harness type declared in the header.
class AttrCommitmentExperimentHarnessP256 {
 public:
  virtual ~AttrCommitmentExperimentHarnessP256() = default;
  virtual bool Prove() = 0;
  virtual void FillPublic(Dense<Field>& pub) const = 0;
  virtual bool Verify(const Dense<Field>& pub) const = 0;
  virtual size_t PublicSize() const = 0;
};

void AttrCommitmentExperimentHarnessP256Deleter::operator()(
    AttrCommitmentExperimentHarnessP256* p) const {
  delete p;
}

namespace {

template <class CtxT>
struct CommonZk {
  std::unique_ptr<Circuit<Field>> circuit;
  Dense<Field> w;
  Field2 field2;
  Field2::Elt omega;
  ConvolutionFactory factory;
  RSFactory rsf;
  SecureRandomEngine rng;
  std::unique_ptr<ZkProof<Field>> zkpr;
  ZkProver<Field, RSFactory> prover;
  ZkVerifier<Field, RSFactory> verifier;
  CtxT ctx;

  explicit CommonZk(std::unique_ptr<Circuit<Field>> c)
      : circuit(std::move(c)),
        w(1, circuit->ninputs),
        field2(p256_base),
        omega(field2.of_string(kP256ExtRootX, kP256ExtRootY)),
        factory(p256_base, field2, omega, kP256ExtRootOrder),
        rsf(factory, p256_base),
        zkpr(std::make_unique<ZkProof<Field>>(*circuit, kRate, kQueries)),
        prover(*circuit, p256_base, rsf),
        verifier(*circuit, rsf, kRate, kQueries, p256_base),
        ctx() {
    set_log_level(ERROR);
  }
};

template <size_t NAttrs>
class FlatHarness final : public AttrCommitmentExperimentHarnessP256 {
 public:
  FlatHarness() : zk_(make_flat_circuit<NAttrs>()) {
    build_inputs();
    fill_flat<NAttrs>(zk_.w, zk_.ctx, /*prover=*/true);
  }
  bool Prove() override {
    zk_.zkpr = std::make_unique<ZkProof<Field>>(*zk_.circuit, kRate, kQueries);
    Transcript tp((uint8_t*)"bench", 5);
    zk_.prover.commit(*zk_.zkpr, zk_.w, tp, zk_.rng);
    return zk_.prover.prove(*zk_.zkpr, zk_.w, tp);
  }
  void FillPublic(Dense<Field>& pub) const override {
    fill_flat<NAttrs>(pub, zk_.ctx, /*prover=*/false);
  }
  bool Verify(const Dense<Field>& pub) const override {
    Transcript tv((uint8_t*)"bench", 5);
    zk_.verifier.recv_commitment(*zk_.zkpr, tv);
    return zk_.verifier.verify(*zk_.zkpr, pub, tv);
  }
  size_t PublicSize() const override { return zk_.circuit->npub_in; }

 private:
  void build_inputs() {
    SecureRandomEngine rng_local;
    std::array<uint8_t, FlatCtx<NAttrs>::kMsgBytes> msg{};
    for (size_t i = 0; i < NAttrs; ++i) {
      random_bytes(rng_local, zk_.ctx.attrs[i]);
      std::memcpy(msg.data() + i * 32, zk_.ctx.attrs[i].data(), 32);
    }
    sha256_bytes(msg.data(), msg.size(), zk_.ctx.digest.data());
    sha256_message_witness<FlatCtx<NAttrs>::kBlocks>(msg.data(), msg.size(),
                                                     zk_.ctx.sha_in, zk_.ctx.sha_bw);

    // Sanity: OpenSSL digest must match last block witness h1.
    std::array<uint8_t, 32> want{};
    const auto& last = zk_.ctx.sha_bw[FlatCtx<NAttrs>::kBlocks - 1];
    for (size_t j = 0; j < 8; ++j) {
      const uint32_t w = last.h1[j];
      want[4 * j + 0] = static_cast<uint8_t>(w >> 24);
      want[4 * j + 1] = static_cast<uint8_t>(w >> 16);
      want[4 * j + 2] = static_cast<uint8_t>(w >> 8);
      want[4 * j + 3] = static_cast<uint8_t>(w);
    }
    check(want == zk_.ctx.digest, "sha witness digest mismatch");
  }

  CommonZk<FlatCtx<NAttrs>> zk_;
};

template <size_t NAttrs, size_t Depth, size_t K>
class MerkleHarness final : public AttrCommitmentExperimentHarnessP256 {
 public:
  MerkleHarness() : zk_(make_merkle_circuit<NAttrs, Depth, K>()) {
    build_inputs();
    fill_merkle<NAttrs, Depth, K>(zk_.w, zk_.ctx, /*prover=*/true);
  }
  bool Prove() override {
    zk_.zkpr = std::make_unique<ZkProof<Field>>(*zk_.circuit, kRate, kQueries);
    Transcript tp((uint8_t*)"bench", 5);
    zk_.prover.commit(*zk_.zkpr, zk_.w, tp, zk_.rng);
    return zk_.prover.prove(*zk_.zkpr, zk_.w, tp);
  }
  void FillPublic(Dense<Field>& pub) const override {
    fill_merkle<NAttrs, Depth, K>(pub, zk_.ctx, /*prover=*/false);
  }
  bool Verify(const Dense<Field>& pub) const override {
    Transcript tv((uint8_t*)"bench", 5);
    zk_.verifier.recv_commitment(*zk_.zkpr, tv);
    return zk_.verifier.verify(*zk_.zkpr, pub, tv);
  }
  size_t PublicSize() const override { return zk_.circuit->npub_in; }

 private:
  static void be32_of_u8(uint8_t out[32], uint8_t x) {
    std::memset(out, 0, 32);
    out[31] = x;
  }

  static void sha256_witness_64(const uint8_t msg64[64],
                               std::array<FlatSHA256Witness::BlockWitness, 2>& out) {
    std::array<uint8_t, 128> tmp{};
    uint8_t numb = 0;
    FlatSHA256Witness::transform_and_witness_message(64, msg64, 2, numb, tmp.data(),
                                                     out.data());
    check(numb == 2, "sha64 witness blocks mismatch");
  }

  static std::array<uint8_t, 32> digest_bytes_from_bw(
      const std::array<FlatSHA256Witness::BlockWitness, 2>& bw) {
    std::array<uint8_t, 32> out{};
    for (size_t j = 0; j < 8; ++j) {
      const uint32_t w = bw[1].h1[j];
      const size_t base = j * 4;
      out[base + 0] = static_cast<uint8_t>(w >> 24);
      out[base + 1] = static_cast<uint8_t>(w >> 16);
      out[base + 2] = static_cast<uint8_t>(w >> 8);
      out[base + 3] = static_cast<uint8_t>(w);
    }
    return out;
  }

  void build_inputs() {
    SecureRandomEngine rng_local;
    for (auto& a : zk_.ctx.attrs) random_bytes(rng_local, a);

    std::array<std::array<uint8_t, 32>, NAttrs> level{};
    for (size_t i = 0; i < NAttrs; ++i) {
      uint8_t msg64[64];
      be32_of_u8(msg64, static_cast<uint8_t>(i));
      std::memcpy(msg64 + 32, zk_.ctx.attrs[i].data(), 32);
      sha256_bytes(msg64, 64, level[i].data());
    }

    std::array<std::array<std::array<uint8_t, 32>, NAttrs>, Depth + 1> tree{};
    tree[0] = level;
    size_t width = NAttrs;
    for (size_t d = 0; d < Depth; ++d) {
      for (size_t j = 0; j < width; j += 2) {
        uint8_t msg64[64];
        std::memcpy(msg64, tree[d][j].data(), 32);
        std::memcpy(msg64 + 32, tree[d][j + 1].data(), 32);
        sha256_bytes(msg64, 64, tree[d + 1][j / 2].data());
      }
      width >>= 1;
    }
    zk_.ctx.root = tree[Depth][0];

    for (size_t claim_i = 0; claim_i < K; ++claim_i) {
      auto& c = zk_.ctx.claims[claim_i];
      c.value_be = zk_.ctx.attrs[claim_i];
      size_t idx = claim_i;

      uint8_t leaf_msg64[64];
      be32_of_u8(leaf_msg64, static_cast<uint8_t>(idx));
      std::memcpy(leaf_msg64 + 32, c.value_be.data(), 32);
      sha256_witness_64(leaf_msg64, c.leaf_bw);
      {
        std::array<uint8_t, 32> want{};
        sha256_bytes(leaf_msg64, 64, want.data());
        const auto got = digest_bytes_from_bw(c.leaf_bw);
        check(got == want, "leaf bw digest bytes mismatch");
      }

      for (size_t d = 0; d < Depth; ++d) {
        const size_t sibling = idx ^ 1;
        const bool is_right = (idx & 1) != 0;
        c.path_indices[d] = is_right ? p256_base.one() : p256_base.zero();
        c.path_elements[d] = tree[d][sibling];

        const auto& left = is_right ? tree[d][sibling] : tree[d][idx];
        const auto& right = is_right ? tree[d][idx] : tree[d][sibling];
        uint8_t msg64[64];
        std::memcpy(msg64, left.data(), 32);
        std::memcpy(msg64 + 32, right.data(), 32);
        sha256_witness_64(msg64, c.node_bw[d]);
        {
          std::array<uint8_t, 32> want{};
          sha256_bytes(msg64, 64, want.data());
          const auto got = digest_bytes_from_bw(c.node_bw[d]);
          check(got == want, "node bw digest bytes mismatch");
        }

        idx >>= 1;
      }

    }
  }

  CommonZk<MerkleCtx<NAttrs, Depth, K>> zk_;
};

template <class T>
static AttrCommitmentExperimentHarnessP256Ptr mk() {
  return AttrCommitmentExperimentHarnessP256Ptr(new T());
}

}  // namespace

AttrCommitmentExperimentHarnessP256Ptr MakeAttrCommitmentExperimentHarnessP256(
    const char* mode, size_t total_attrs, size_t used_attrs) {
  const std::string_view m(mode ? mode : "");
  const bool is_flat = (m == "flat");
  const bool is_merkle = (m == "merkle");
  check(is_flat || is_merkle, "mode must be 'flat' or 'merkle'");
  auto bad = [&]() -> AttrCommitmentExperimentHarnessP256Ptr {
    check(false, "unsupported (n,k)");
    return AttrCommitmentExperimentHarnessP256Ptr(nullptr);
  };

  if (is_flat) {
    if (total_attrs == 8) return mk<FlatHarness<8>>();
    if (total_attrs == 16) return mk<FlatHarness<16>>();
    if (total_attrs == 32) return mk<FlatHarness<32>>();
    if (total_attrs == 64) return mk<FlatHarness<64>>();
    return bad();
  }

  if (total_attrs == 8) {
    if (used_attrs == 1) return mk<MerkleHarness<8, 3, 1>>();
    if (used_attrs == 2) return mk<MerkleHarness<8, 3, 2>>();
    if (used_attrs == 4) return mk<MerkleHarness<8, 3, 4>>();
    if (used_attrs == 8) return mk<MerkleHarness<8, 3, 8>>();
    return bad();
  }
  if (total_attrs == 16) {
    if (used_attrs == 1) return mk<MerkleHarness<16, 4, 1>>();
    if (used_attrs == 2) return mk<MerkleHarness<16, 4, 2>>();
    if (used_attrs == 4) return mk<MerkleHarness<16, 4, 4>>();
    if (used_attrs == 8) return mk<MerkleHarness<16, 4, 8>>();
    if (used_attrs == 16) return mk<MerkleHarness<16, 4, 16>>();
    return bad();
  }
  if (total_attrs == 32) {
    if (used_attrs == 1) return mk<MerkleHarness<32, 5, 1>>();
    if (used_attrs == 2) return mk<MerkleHarness<32, 5, 2>>();
    if (used_attrs == 4) return mk<MerkleHarness<32, 5, 4>>();
    if (used_attrs == 8) return mk<MerkleHarness<32, 5, 8>>();
    if (used_attrs == 16) return mk<MerkleHarness<32, 5, 16>>();
    return bad();
  }
  if (total_attrs == 64) {
    if (used_attrs == 1) return mk<MerkleHarness<64, 6, 1>>();
    if (used_attrs == 2) return mk<MerkleHarness<64, 6, 2>>();
    if (used_attrs == 4) return mk<MerkleHarness<64, 6, 4>>();
    if (used_attrs == 8) return mk<MerkleHarness<64, 6, 8>>();
    if (used_attrs == 16) return mk<MerkleHarness<64, 6, 16>>();
    return bad();
  }
  return bad();
}

bool ProveAttrCommitmentExperimentP256(AttrCommitmentExperimentHarnessP256& h) {
  return h.Prove();
}

std::unique_ptr<Dense<Fp256Base>> PublicInputsAttrCommitmentExperimentP256(
    const AttrCommitmentExperimentHarnessP256& h) {
  auto pub = std::make_unique<Dense<Fp256Base>>(1, h.PublicSize());
  h.FillPublic(*pub);
  return pub;
}

bool VerifyAttrCommitmentExperimentP256(const AttrCommitmentExperimentHarnessP256& h,
                                       const Dense<Fp256Base>& pub) {
  return h.Verify(pub);
}

}  // namespace proofs

