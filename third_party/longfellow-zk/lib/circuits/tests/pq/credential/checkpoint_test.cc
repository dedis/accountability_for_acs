// ProverLayers::prove_low_memory (packed layers, checkpointed layers, the
// first copy round in the base field, the copy rounds with EQ factored out)
// gives the same sumcheck proof as the upstream dense prover (eval_circuit,
// then prove), with a random pad, on the sponge circuit (sponge.h) over
// GF(2^256) (26 layers) and Fq^12 (145 layers, with full wires in Fq), for
// 1, 2, 3, 8, 37 and 64 copies.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <vector>

#include "algebra/fp24_ext.h"
#include "arrays/packed_layer.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/credential/sponge.h"
#include "circuits/tests/pq/credential/statement.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "gf2k/gf2_128_ext.h"
#include "random/transcript.h"
#include "sumcheck/prover_layers.h"
#include "sumcheck/transcript_sumcheck.h"
#include "gtest/gtest.h"

namespace proofs {
namespace pq_cred {
namespace {

template <class Field>
class Prover : public ProverLayers<Field> {
 public:
  explicit Prover(const Field& f) : ProverLayers<Field>(f) {}

  // The sumcheck proof of CIRCUIT on W with the given checkpoint stride,
  // or, with DENSE, with the upstream prover; null if the packed prover
  // fails (an assertion or a nonzero output).
  std::unique_ptr<Proof<Field>> run(const Circuit<Field>& circuit,
                                    const PackedLayer<Field>& w, size_t stride,
                                    bool dense, const Field& f) {
    auto pr = std::make_unique<Proof<Field>>(circuit.nl);
    Proof<Field> pad(circuit.nl);
    Transcript rng((uint8_t*)"pad", 3);
    for (auto& l : pad.l) {
      for (auto& c : l.cp) for (auto& x : c.t_) x = rng.elt(f);
      for (auto& h : l.hp)
        for (auto& p : h)
          for (auto& x : p.t_) x = rng.elt(f);
      l.wc[0] = rng.elt(f);
      l.wc[1] = rng.elt(f);
    }
    Transcript t((uint8_t*)"checkpoint", 10);
    TranscriptSumcheck<Field> ts(t, f);
    typename ProverLayers<Field>::bindings bnd;
    if (dense) {
      auto d = std::make_unique<Dense<Field>>(w.n0(), w.n1());
      w.unpack(*d);
      typename ProverLayers<Field>::inputs in;
      EXPECT_NE(this->eval_circuit(&in, &circuit, std::move(d), f), nullptr);
      this->prove(pr.get(), &pad, &circuit, in, nullptr, bnd, ts, f);
    } else if (!this->prove_low_memory(pr.get(), &pad, &circuit, w, nullptr,
                                       bnd, ts, f, stride)) {
      return nullptr;
    }
    return pr;
  }
};

template <class Elt, size_t N>
bool same(const Elt (&a)[N], const Elt (&b)[N]) {
  return std::equal(a, a + N, b);
}

// The sponge of a LEN-byte message has ceil((LEN + 1) / 136) copies.
template <class Field>
void SameProof(const Field& f, size_t len, size_t want_nc,
               std::initializer_list<size_t> strides) {
  using LC = Logic<Field, CompilerBackend<Field>>;
  Links<Field> links(f);
  Sponge<Field> sp(0, links);
  std::vector<uint8_t> msg(len);
  for (size_t i = 0; i < len; ++i) msg[i] = uint8_t(7 + 31 * i);
  sp.shake(kShake256Rate, free_bytes(msg.data(), len), 64);
  const size_t nc = sp.copies().size();
  ASSERT_EQ(nc, want_nc);

  QuadCircuit<Field> Q(f);
  const CompilerBackend<Field> cbk(&Q);
  const LC lc(&cbk, f);
  typename SpongeStep<LC>::Public u;
  typename SpongeStep<LC>::Private w;
  Sponge<Field>::inputs(lc, Q, u, w);
  Q.begin_full_field();
  SpongeStep<LC>(lc).assert_step(u, w);
  const auto circuit = Q.mkcircuit(nc);

  PackedLayer<Field> in(nc, circuit->ninputs, f);
  for (size_t c = 0; c < nc; ++c) sp.fill(in, c, false);

  Prover<Field> prover(f);
  const auto want = prover.run(*circuit, in, 0, /*dense=*/true, f);
  for (size_t stride : strides) {
    const auto got = prover.run(*circuit, in, stride, /*dense=*/false, f);
    ASSERT_NE(got, nullptr);
    for (size_t ly = 0; ly < circuit->nl; ++ly) {
      const auto &a = want->l[ly], &b = got->l[ly];
      EXPECT_TRUE(a.wc[0] == b.wc[0] && a.wc[1] == b.wc[1])
          << "copies " << nc << " stride " << stride << " layer " << ly;
      for (size_t r = 0; r < circuit->logc; ++r) {
        EXPECT_TRUE(same(a.cp[r].t_, b.cp[r].t_))
            << "copies " << nc << " stride " << stride << " layer " << ly;
      }
      for (size_t h = 0; h < 2; ++h) {
        for (size_t r = 0; r < circuit->l[ly].logw; ++r) {
          EXPECT_TRUE(same(a.hp[h][r].t_, b.hp[h][r].t_))
              << "copies " << nc << " stride " << stride;
        }
      }
    }
  }
}

// A witness with one private input bit changed (the last one, of copy 1)
// fails an assertion: prove_low_memory returns false.
template <class Field>
void RejectsWrongWitness(const Field& f) {
  using LC = Logic<Field, CompilerBackend<Field>>;
  Links<Field> links(f);
  Sponge<Field> sp(0, links);
  std::vector<uint8_t> msg(300, 7);
  sp.shake(kShake256Rate, free_bytes(msg.data(), msg.size()), 64);
  const size_t nc = sp.copies().size();
  QuadCircuit<Field> Q(f);
  const CompilerBackend<Field> cbk(&Q);
  const LC lc(&cbk, f);
  typename SpongeStep<LC>::Public u;
  typename SpongeStep<LC>::Private w;
  Sponge<Field>::inputs(lc, Q, u, w);
  Q.begin_full_field();
  SpongeStep<LC>(lc).assert_step(u, w);
  const auto circuit = Q.mkcircuit(nc);
  PackedLayer<Field> in(nc, circuit->ninputs, f);
  for (size_t c = 0; c < nc; ++c) sp.fill(in, c, false);
  Dense<Field> d(nc, circuit->ninputs);
  in.unpack(d);
  Prover<Field> prover(f);
  for (size_t stride : {0, 1}) {
    EXPECT_NE(prover.run(*circuit, PackedLayer<Field>(d, f), stride, false, f),
              nullptr);
  }
  auto& x = d.v_[nc * (circuit->ninputs - 1) + 1];
  x = x == f.zero() ? f.one() : f.zero();
  for (size_t stride : {0, 1}) {
    EXPECT_EQ(prover.run(*circuit, PackedLayer<Field>(d, f), stride, false, f),
              nullptr);
  }
}

template <class Field>
void SameProofs(const Field& f) {
  SameProof(f, 300, 3, {0, 1, 2, 3, 7, 1000});
  SameProof(f, 100, 1, {0});
  SameProof(f, 200, 2, {0});
  SameProof(f, 1000, 8, {0, 1});
  SameProof(f, 4946, 37, {0});
  SameProof(f, 8578, 64, {0});
}

TEST(Checkpoint, RejectsWrongWitnessGf2) {
  RejectsWrongWitness(GF2_128Ext<2>());
}

TEST(Checkpoint, RejectsWrongWitnessFq12) {
  RejectsWrongWitness(Fp24Ext<12>(ml_dsa::Fq(), 7));
}

TEST(Checkpoint, SameProofGf2) { SameProofs(GF2_128Ext<2>()); }

TEST(Checkpoint, SameProofFq12) {
  SameProofs(Fp24Ext<12>(ml_dsa::Fq(), 7));
}

}  // namespace
}  // namespace pq_cred
}  // namespace proofs
