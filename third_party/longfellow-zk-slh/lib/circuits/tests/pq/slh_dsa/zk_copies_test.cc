// ZK proofs over several copies of one circuit, linked by extra linear
// constraints (not upstream; see zk/zk_common.h).
//
// Each copy has a public byte A and private bytes X, Y, and asserts
// Y = (X AND A) XOR X. The extra constraints chain the copies:
// X of copy c + 1 = Y of copy c.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "ligero/ligero_param.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/prover_layers.h"
#include "sumcheck/transcript_sumcheck.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_common.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = GF2_128<>;
using Elt = Field::Elt;
using RSFactory = LCH14ReedSolomonFactory<Field>;
using Extra = ZkCommon<Field>::ExtraConstraints;
using Llc = LigeroLinearConstraint<Field>;

constexpr size_t kRate = 4;
constexpr size_t kQueries = 128;
// Input layout of one copy: one, A (public, inputs 1-8), X, Y (private).
constexpr size_t kX = 9, kY = 17, kInputs = 25;

const Field F;

std::unique_ptr<Circuit<Field>> make_circuit(size_t nc) {
  QuadCircuit<Field> Q(F);
  const CompilerBackend<Field> cbk(&Q);
  const Logic<Field, CompilerBackend<Field>> L(&cbk, F);
  auto a = L.vinput<8>();
  Q.private_input();
  auto x = L.vinput<8>();
  auto y = L.vinput<8>();
  L.vassert_eq(y, L.vxor(L.vand(x, a), x));
  return Q.mkcircuit(nc);
}

struct Instance {
  std::vector<uint8_t> a, x, y;
};

Instance make_instance(size_t nc) {
  Instance in;
  uint8_t x = 0xA5;
  for (size_t c = 0; c < nc; ++c) {
    const uint8_t a = static_cast<uint8_t>(0x3C + 17 * c);
    const uint8_t y = static_cast<uint8_t>((x & a) ^ x);
    in.a.push_back(a);
    in.x.push_back(x);
    in.y.push_back(y);
    x = y;
  }
  return in;
}

// Inputs of all copies in the prover layout: input I of copy C at nc*I + C.
// With PUBLIC_ONLY, only the public inputs.
std::unique_ptr<Dense<Field>> fill(const Instance& in, size_t ninputs,
                                   bool public_only) {
  const size_t nc = in.a.size();
  auto w = std::make_unique<Dense<Field>>(nc, public_only ? kX : ninputs);
  for (size_t c = 0; c < nc; ++c) {
    Dense<Field> one(1, kInputs);
    DenseFiller<Field> f(one);
    f.push_back(F.one());
    f.push_back(in.a[c], 8, F);
    f.push_back(in.x[c], 8, F);
    f.push_back(in.y[c], 8, F);
    for (size_t i = 0; i < w->n1_; ++i) w->v_[nc * i + c] = one.v_[i];
  }
  return w;
}

// X of copy c + 1 equals Y of copy c, bit by bit.
Extra make_links(const Circuit<Field>& circuit) {
  Extra e;
  size_t row = 0;
  for (size_t c = 0; c + 1 < circuit.nc; ++c) {
    for (size_t b = 0; b < 8; ++b) {
      e.a.push_back(Llc{row,
                        ZkCommon<Field>::witness_index(circuit, kX + b, c + 1),
                        F.one()});
      e.a.push_back(Llc{row, ZkCommon<Field>::witness_index(circuit, kY + b, c),
                        F.mone()});
      e.b.push_back(F.zero());
      ++row;
    }
  }
  return e;
}

struct ProofRun {
  std::unique_ptr<Circuit<Field>> circuit;
  std::unique_ptr<ZkProof<Field>> proof;
};

ProofRun prove(const Instance& in, const Extra* extra_override = nullptr) {
  ProofRun r;
  r.circuit = make_circuit(in.a.size());
  EXPECT_EQ(r.circuit->ninputs, kInputs);
  EXPECT_EQ(r.circuit->npub_in, kX);
  const Extra links = make_links(*r.circuit);
  const Extra* extra = extra_override ? extra_override : &links;
  auto w = fill(in, r.circuit->ninputs, false);
  r.proof = std::make_unique<ZkProof<Field>>(*r.circuit, kRate, kQueries);
  const RSFactory rsf(F);
  ZkProver<Field, RSFactory> prover(*r.circuit, F, rsf);
  SecureRandomEngine rng;
  Transcript tp((uint8_t*)"copies", 6);
  prover.commit(*r.proof, *w, tp, rng);
  EXPECT_TRUE(prover.prove(*r.proof, *w, tp, extra));
  return r;
}

bool verify(const ProofRun& r, const Instance& in, const Extra& extra) {
  auto pub = fill(in, r.circuit->ninputs, true);
  const RSFactory rsf(F);
  ZkVerifier<Field, RSFactory> verifier(*r.circuit, rsf, kRate, kQueries, F);
  Transcript tv((uint8_t*)"copies", 6);
  verifier.recv_commitment(*r.proof, tv);
  return verifier.verify(*r.proof, *pub, tv, &extra);
}

TEST(ZkCopies, ProvesAndVerifies) {
  set_log_level(ERROR);
  for (size_t nc : {1, 2, 3, 8, 13}) {
    const Instance in = make_instance(nc);
    ProofRun r = prove(in);
    EXPECT_TRUE(verify(r, in, make_links(*r.circuit))) << "nc=" << nc;
  }
}

TEST(ZkCopies, RejectsChangedPublicInput) {
  set_log_level(ERROR);
  const Instance in = make_instance(5);
  ProofRun r = prove(in);
  for (size_t c = 0; c < 5; ++c) {
    Instance bad = in;
    bad.a[c] ^= 0x10;
    EXPECT_FALSE(verify(r, bad, make_links(*r.circuit))) << "copy " << c;
  }
}

TEST(ZkCopies, RejectsBrokenLink) {
  set_log_level(ERROR);
  // Each copy is valid alone, but X of copy 3 is not Y of copy 2.
  Instance in = make_instance(5);
  in.x[3] ^= 0x01;
  in.y[3] = static_cast<uint8_t>((in.x[3] & in.a[3]) ^ in.x[3]);
  ProofRun r = prove(in);
  EXPECT_FALSE(verify(r, in, make_links(*r.circuit)));
}

TEST(ZkCopies, RejectsOtherStatement) {
  set_log_level(ERROR);
  const Instance in = make_instance(4);
  ProofRun r = prove(in);
  // The verifier checks the links against its own constraint list. Another
  // list is another statement, even one the proved witness satisfies: here
  // an extra row fixes bit 0 of X in copy 0, which is 1 (0xA5).
  Extra other = make_links(*r.circuit);
  other.b.push_back(F.one());
  other.a.push_back(Llc{other.b.size() - 1, 0, F.one()});
  EXPECT_FALSE(verify(r, in, other));

  // Out-of-range rows or columns are rejected.
  Extra bad_row = make_links(*r.circuit);
  bad_row.a.push_back(Llc{bad_row.b.size(), 0, F.one()});
  EXPECT_FALSE(verify(r, in, bad_row));
  Extra bad_col = make_links(*r.circuit);
  bad_col.a[0].w = ZkCommon<Field>::num_witness(*r.circuit);
  EXPECT_FALSE(verify(r, in, bad_col));
}

TEST(ZkCopies, RejectsChangedCopyRound) {
  set_log_level(ERROR);
  const Instance in = make_instance(8);
  ProofRun r = prove(in);
  ASSERT_GT(r.circuit->logc, 0u);
  for (size_t ly : {size_t(0), r.circuit->nl - 1}) {
    for (size_t k : {0, 2, 3}) {
      ProofRun bad;
      bad.circuit = make_circuit(8);
      bad.proof =
          std::make_unique<ZkProof<Field>>(*bad.circuit, kRate, kQueries);
      std::vector<uint8_t> buf;
      r.proof->write(buf, F);
      ReadBuffer rb(buf);
      ASSERT_TRUE(bad.proof->read(rb, F));
      F.add(bad.proof->proof.l[ly].cp[0].t_[k], F.one());
      EXPECT_FALSE(verify(bad, in, make_links(*r.circuit)))
          << "layer " << ly << " point " << k;
    }
  }
}

// The commitment holds a witness whose copy 2 is wrong; the sumcheck runs on
// the right witness. The input binding over all copies must catch it.
TEST(ZkCopies, RejectsWitnessNotCommitted) {
  set_log_level(ERROR);
  const Instance in = make_instance(5);
  Instance wrong = in;
  wrong.y[2] ^= 0x40;
  auto circuit = make_circuit(5);
  const Extra links = make_links(*circuit);
  auto good_w = fill(in, circuit->ninputs, false);
  auto wrong_w = fill(wrong, circuit->ninputs, false);
  ProofRun r;
  r.proof = std::make_unique<ZkProof<Field>>(*circuit, kRate, kQueries);
  const RSFactory rsf(F);
  ZkProver<Field, RSFactory> prover(*circuit, F, rsf);
  SecureRandomEngine rng;
  Transcript tp((uint8_t*)"copies", 6);
  prover.commit(*r.proof, *wrong_w, tp, rng);
  ASSERT_TRUE(prover.prove(*r.proof, *good_w, tp, &links));
  r.circuit = std::move(circuit);
  EXPECT_FALSE(verify(r, in, links));
}

uint32_t get_u32(const std::vector<uint8_t>& b, size_t at) {
  uint32_t v = 0;
  for (size_t i = 0; i < 4; ++i) v |= uint32_t(b[at + i]) << (8 * i);
  return v;
}

void put_u32(std::vector<uint8_t>& b, uint32_t v) {
  for (size_t i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i)));
}

// Every proof has one encoding (zk_proof.h, merkle_tree.h): trailing bytes,
// another chunking of the opened columns and unused Merkle digests are
// rejected.
TEST(ZkCopies, RejectsNonCanonicalEncodings) {
  set_log_level(ERROR);
  const size_t nc = 6;
  const Instance in = make_instance(nc);
  ProofRun r = prove(in);
  std::vector<uint8_t> buf;
  r.proof->write(buf, F);
  const Extra links = make_links(*r.circuit);
  auto accepted = [&](const std::vector<uint8_t>& bytes) {
    ProofRun p;
    p.circuit = make_circuit(nc);
    p.proof = std::make_unique<ZkProof<Field>>(*p.circuit, kRate, kQueries);
    ReadBuffer rb(bytes);
    return p.proof->read(rb, F) && verify(p, in, links);
  };
  ASSERT_TRUE(accepted(buf));

  std::vector<uint8_t> trailing = buf;
  trailing.push_back(0);
  EXPECT_FALSE(accepted(trailing));

  // Offset of the opened columns, after the commitment, the sumcheck proof,
  // the Ligero responses and the nonces.
  const auto& c = *r.circuit;
  const auto& cp = r.proof->com_proof;
  size_t runs = Digest::kLength;
  for (size_t i = 0; i < c.nl; ++i) {
    runs += (c.logc * 3 + c.l[i].logw * 4 + 2) * Field::kBytes;
  }
  runs +=
      (cp.block + cp.dblock + cp.r + (cp.dblock - cp.block)) * Field::kBytes +
      cp.nreq * MerkleNonce::kLength;
  const size_t total = cp.nreq * cp.nrow;
  size_t path = runs;
  bool sub = false;
  for (size_t ci = 0; ci < total; sub = !sub) {
    const uint32_t len = get_u32(buf, path);
    path += 4 + len * (sub ? Field::kSubFieldBytes : Field::kBytes);
    ci += len;
  }

  // The same columns in runs of at most 7 elements.
  std::vector<uint8_t> rechunked(buf.begin(), buf.begin() + runs);
  sub = false;
  for (size_t ci = 0; ci < total; sub = !sub) {
    size_t len = 0;
    while (ci + len < total && len < 7 &&
           F.in_subfield(cp.req[ci + len]) == sub) {
      ++len;
    }
    put_u32(rechunked, uint32_t(len));
    for (size_t i = ci; i < ci + len; ++i) {
      uint8_t tmp[Field::kBytes];
      if (sub) {
        F.to_bytes_subfield(tmp, cp.req[i]);
        rechunked.insert(rechunked.end(), tmp, tmp + Field::kSubFieldBytes);
      } else {
        F.to_bytes_field(tmp, cp.req[i]);
        rechunked.insert(rechunked.end(), tmp, tmp + Field::kBytes);
      }
    }
    ci += len;
  }
  rechunked.insert(rechunked.end(), buf.begin() + path, buf.end());
  ASSERT_NE(rechunked, buf);
  EXPECT_FALSE(accepted(rechunked));

  // One unused zero digest after the Merkle path.
  std::vector<uint8_t> longer(buf.begin(), buf.begin() + path);
  put_u32(longer, get_u32(buf, path) + 1);
  longer.insert(longer.end(), buf.begin() + path + 4, buf.end());
  longer.insert(longer.end(), Digest::kLength, 0);
  EXPECT_FALSE(accepted(longer));
}

// ProverLayers::prove_low_memory (packed layers) gives the same sumcheck
// proof as eval_circuit() followed by prove(), and rejects a false copy.
struct LayersProver : ProverLayers<Field> {
  using ProverLayers<Field>::ProverLayers;
  using ProverLayers<Field>::prove;
  using ProverLayers<Field>::prove_low_memory;
  using typename ProverLayers<Field>::bindings;
};

// Y = f(X, A) with f six rounds of t = t AND (t XOR A): a deeper circuit,
// with the input layout of make_circuit.
constexpr size_t kDepth = 6;

uint8_t deep(uint8_t x, uint8_t a) {
  for (size_t i = 0; i < kDepth; ++i) x = x & (x ^ a);
  return x;
}

std::unique_ptr<Circuit<Field>> make_deep_circuit(size_t nc) {
  QuadCircuit<Field> Q(F);
  const CompilerBackend<Field> cbk(&Q);
  const Logic<Field, CompilerBackend<Field>> L(&cbk, F);
  auto a = L.vinput<8>();
  Q.private_input();
  auto x = L.vinput<8>();
  auto y = L.vinput<8>();
  for (size_t i = 0; i < kDepth; ++i) x = L.vand(x, L.vxor(x, a));
  L.vassert_eq(y, x);
  return Q.mkcircuit(nc);
}

// V = U^3 over field elements: with U = 0 or 1 in some copies and not in
// others, a wire is 0/1 in some copies only, so PackedLayer stores it in full.
std::unique_ptr<Circuit<Field>> make_cube_circuit(size_t nc) {
  QuadCircuit<Field> Q(F);
  const CompilerBackend<Field> cbk(&Q);
  const Logic<Field, CompilerBackend<Field>> L(&cbk, F);
  Q.private_input();
  auto u = L.eltw_input();
  auto v = L.eltw_input();
  L.assert_eq(v, L.mul(u, L.mul(u, u)));
  return Q.mkcircuit(nc);
}

std::unique_ptr<Dense<Field>> cube_inputs(size_t nc, bool valid) {
  auto w = std::make_unique<Dense<Field>>(nc, 3);
  for (size_t c = 0; c < nc; ++c) {
    const auto u = F.of_scalar(c % 2 == 0 ? c % 4 / 2 : 3 + c);
    w->v_[c] = F.one();
    w->v_[nc + c] = u;
    w->v_[2 * nc + c] = F.mulf(u, F.mulf(u, u));
  }
  if (!valid) F.add(w->v_[2 * nc + nc - 1], F.one());
  return w;
}

// prove_low_memory on INPUTS gives the sumcheck proof of eval_circuit()
// followed by prove().
void expect_same_proof(
    const Circuit<Field>& c,
    const std::function<std::unique_ptr<Dense<Field>>()>& inputs) {
  LayersProver p(F);
  Proof<Field> want(c.nl), got(c.nl);
  {
    LayersProver::inputs layers;
    ASSERT_NE(p.eval_circuit(&layers, &c, inputs(), F), nullptr);
    Transcript t((uint8_t*)"layers", 6);
    TranscriptSumcheck<Field> ts(t, F);
    LayersProver::bindings bnd;
    p.prove(&want, nullptr, &c, layers, nullptr, bnd, ts, F);
  }
  {
    Transcript t((uint8_t*)"layers", 6);
    TranscriptSumcheck<Field> ts(t, F);
    LayersProver::bindings bnd;
    const PackedLayer<Field> packed(*inputs(), F);
    ASSERT_TRUE(
        p.prove_low_memory(&got, nullptr, &c, packed, nullptr, bnd, ts, F));
  }
  for (size_t ly = 0; ly < c.nl; ++ly) {
    for (size_t r = 0; r < c.logc; ++r) {
      for (size_t k : {0, 2, 3}) {
        EXPECT_EQ(got.l[ly].cp[r].t_[k], want.l[ly].cp[r].t_[k]);
      }
    }
    for (size_t r = 0; r < c.l[ly].logw; ++r) {
      for (size_t h = 0; h < 2; ++h) {
        for (size_t k : {0, 2}) {
          EXPECT_EQ(got.l[ly].hp[h][r].t_[k], want.l[ly].hp[h][r].t_[k]);
        }
      }
    }
    EXPECT_EQ(got.l[ly].wc[0], want.l[ly].wc[0]);
    EXPECT_EQ(got.l[ly].wc[1], want.l[ly].wc[1]);
  }
}

bool prove_low_memory(const Circuit<Field>& c,
                      std::unique_ptr<Dense<Field>> inputs) {
  LayersProver p(F);
  Proof<Field> got(c.nl);
  Transcript t((uint8_t*)"layers", 6);
  TranscriptSumcheck<Field> ts(t, F);
  LayersProver::bindings bnd;
  const PackedLayer<Field> packed(*inputs, F);
  return p.prove_low_memory(&got, nullptr, &c, packed, nullptr, bnd, ts, F);
}

TEST(ZkCopies, LowMemoryProverMatches) {
  // Odd counts and counts around the 64-bit words of the packed wires.
  for (size_t nc : {1, 2, 3, 8, 63, 64, 65, 129}) {
    // Bits only.
    auto deep_c = make_deep_circuit(nc);
    Instance in = make_instance(nc);
    for (size_t i = 0; i < nc; ++i) in.y[i] = deep(in.x[i], in.a[i]);
    expect_same_proof(*deep_c,
                      [&] { return fill(in, deep_c->ninputs, false); });
    Instance bad = in;
    bad.y[nc - 1] ^= 1;
    EXPECT_FALSE(prove_low_memory(*deep_c, fill(bad, deep_c->ninputs, false)));

    // Wires that are 0/1 in some copies only.
    auto cube_c = make_cube_circuit(nc);
    expect_same_proof(*cube_c, [&] { return cube_inputs(nc, true); });
    EXPECT_FALSE(prove_low_memory(*cube_c, cube_inputs(nc, false)));
  }
}

TEST(ZkCopies, SerializationRoundTrip) {
  set_log_level(ERROR);
  const Instance in = make_instance(6);
  ProofRun r = prove(in);
  std::vector<uint8_t> buf;
  r.proof->write(buf, F);
  ProofRun copy;
  copy.circuit = std::move(r.circuit);
  copy.proof = std::make_unique<ZkProof<Field>>(*copy.circuit, kRate, kQueries);
  ReadBuffer rb(buf);
  ASSERT_TRUE(copy.proof->read(rb, F));
  EXPECT_TRUE(verify(copy, in, make_links(*copy.circuit)));
}

}  // namespace
}  // namespace proofs
