// SLH-DSA ZK proofs and benchmarks (not upstream); see slh_dsa_zk.h. Built
// twice: slh_dsa_zk_test (48-byte digests) has the category 3 sets 192s and
// 192f, slh_dsa_zk_5_test (64-byte digests) the category 5 sets 256s and
// 256f.

#include <chrono>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/tests/pq/slh_dsa/slh_dsa.h"
#include "circuits/tests/pq/slh_dsa/slh_dsa_examples.h"
#include "circuits/tests/pq/slh_dsa/slh_dsa_zk.h"
#include "sumcheck/prover_layers.h"
#include "util/log.h"
#include "zk/zk_soundness.h"
#include "util/panic.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace slh_dsa {
namespace {

template <class P>
void ProveAndVerify(const Example& ex) {
  set_log_level(ERROR);
  auto zk = SlhDsaZk<P>::Make(ex.pk, ex.ctx, ex.msg.size());
  ASSERT_NE(zk, nullptr);
  ASSERT_TRUE(zk->Prove(ex.msg, ex.sig));
  EXPECT_TRUE(zk->Verify());
  EXPECT_FALSE(zk->Verify(/*tamper=*/true));
  std::vector<uint8_t> sig = ex.sig;
  sig[sig.size() / 2] ^= 1;
  EXPECT_FALSE(zk->Prove(ex.msg, sig));

  // Wrong lengths are rejected without aborting.
  EXPECT_FALSE(zk->Prove(std::vector<uint8_t>(ex.msg.size() + 1), ex.sig));
  sig = ex.sig;
  sig.pop_back();
  EXPECT_FALSE(zk->Prove(ex.msg, sig));
  std::vector<uint8_t> pk = ex.pk;
  pk.pop_back();
  EXPECT_EQ(SlhDsaZk<P>::Make(pk, ex.ctx, ex.msg.size()), nullptr);
  EXPECT_EQ(SlhDsaZk<P>::Make(ex.pk, std::vector<uint8_t>(256), 0), nullptr);
  EXPECT_EQ(SlhDsaZk<P>::Make(ex.pk, ex.ctx,
                              SlhDsaZk<P>::kMaxMessageBytes + 1),
            nullptr);
}

#if PROOFS_SHAKE256_DIGEST_BYTES == 64
TEST(SlhDsaZk, Shake256s) { ProveAndVerify<SlhDsaShake256s>(Example256s()); }
#else
TEST(SlhDsaZk, Shake192s) { ProveAndVerify<SlhDsaShake192s>(Example192s()); }
#endif

// Size of one copy of the step circuit, per layer.
template <class P>
void PrintStepCircuitSize() {
  const size_t n = P::n;
  auto c = SlhDsaZk<P>::make_circuit(1);
  {
    size_t wires = 0;
    for (size_t ly = 0; ly < c->nl; ++ly) {
      printf("n=%zu layer %2zu: nw=%7zu nterms=%8zu\n", n, ly,
             size_t(c->l[ly].nw), c->l[ly].nterms());
      wires += c->l[ly].nw;
    }
    printf("n=%zu: nl=%zu ninputs=%zu npub=%zu wires=%zu nterms=%zu\n", n,
           c->nl, c->ninputs, c->npub_in, wires, c->nterms());
  }
}

TEST(SlhDsaZk, StepCircuitSize) {
#if PROOFS_SHAKE256_DIGEST_BYTES == 64
  PrintStepCircuitSize<SlhDsaShake256s>();
#else
  PrintStepCircuitSize<SlhDsaShake192s>();
#endif
}

// Soundness bits of a configuration on the statement of an example, which
// must reach WANT (the NIST category: AES-192 or AES-256 key search).
template <class P, class Z>
void ExpectSoundness(const char* name, const Example& ex, double want) {
  using Zk = SlhDsaZk<P, Z>;
  const Plan<P> plan(ex.pk, ex.ctx, std::vector<uint8_t>(ex.msg.size()),
                     std::vector<uint8_t>(P::sig_bytes));
  const auto circuit = Zk::make_circuit(plan.copies.size());
  const ZkProof<typename Zk::Field> proof(*circuit, Zk::kLigeroRate,
                                          Zk::kLigeroQueries);
  const ZkSoundness s = zk_soundness(*circuit, proof.param,
                                     double(Zk::Field::kBits));
  printf("%s %zu-bit field, %zu queries: sumcheck %.1f proximity %.1f "
         "field %.1f linear %.1f total %.1f\n",
         name, size_t(Zk::Field::kBits), Zk::kLigeroQueries, s.sumcheck,
         s.proximity, s.field, s.linear, s.total);
  EXPECT_GE(s.total, want);
}

TEST(SlhDsaZk, Soundness) {
#if PROOFS_SHAKE256_DIGEST_BYTES == 64
  ExpectSoundness<SlhDsaShake256s, ZkCategory5>("256s", Example256s(), 256);
  ExpectSoundness<SlhDsaShake256f, ZkCategory5>("256f", Example256f(), 256);
#else
  ExpectSoundness<SlhDsaShake192s, ZkCategory3>("192s", Example192s(), 192);
  ExpectSoundness<SlhDsaShake192f, ZkCategory3>("192f", Example192f(), 192);
#endif
}

#if PROOFS_SHAKE256_DIGEST_BYTES != 64

// ProverLayers::eval_layer (packed input and output, by output wire)
// selects bit factors and skips multiplications by a coefficient of one. It
// must give the values and the assertion results of the original formula
// V[g,c] += v * W[l,c] * W[r,c].
using Field = ZkCategory3::Field;

struct EvalProver : ProverLayers<Field> {
  using ProverLayers<Field>::ProverLayers;
  using ProverLayers<Field>::eval_layer;
  using ProverLayers<Field>::PackedLayer;
  using ProverLayers<Field>::ecorner;

  // eval_layer of W into V (NV wires).
  bool eval(const Quad<Field>& quad, corner_t nv, const Dense<Field>& W,
            Dense<Field>* V, const Field& F) {
    std::vector<ecorner> terms(quad.size());
    std::vector<size_t> start(nv + 1);
    std::vector<Field::Elt> row(W.n0_);
    PackedLayer out(W.n0_, nv, F);
    if (!eval_layer(&quad, nv, PackedLayer(W, F), &out, terms, start, row,
                    F)) {
      return false;
    }
    out.unpack(*V);
    return true;
  }
};

// The upstream eval_quad, term by term and copy by copy.
bool reference_eval(const Quad<Field>& quad, Dense<Field>* V,
                    const Dense<Field>& W, const Field& F) {
  const corner_t n0 = V->n0_;
  V->clear(F);
  for (const auto& ec : quad) {
    for (corner_t c = 0; c < n0; ++c) {
      Field::Elt x = F.mulf(W.v_[n0 * ec.h[1] + c], W.v_[n0 * ec.h[0] + c]);
      if (ec.v == F.zero()) {
        if (x != F.zero()) return false;
      } else {
        F.add(V->v_[n0 * ec.g + c], F.mulf(ec.v, x));
      }
    }
  }
  return true;
}

TEST(SlhDsaZk, EvalShortcutsMatchReference) {
  using P = SlhDsaShake192s;
  const Field F;
  const Example ex = Example192s();
  const Plan<P> plan(ex.pk, ex.ctx, ex.msg, ex.sig);
  ASSERT_TRUE(plan.native_ok);

  // One copy of each kind: the message hash, a FORS leaf, a Merkle step, an
  // inactive and an active WOTS+ step, a checksum step, a later block.
  std::vector<size_t> pick = {0, 1, 2};
  auto first = [&](auto pred) {
    for (size_t c = 0; c < plan.copies.size(); ++c) {
      if (pred(plan.copies[c])) return c;
    }
    return size_t(0);
  };
  pick.push_back(first([](const Copy& cp) { return cp.swap_en; }));
  pick.push_back(first([](const Copy& cp) { return cp.is_wots && cp.j < cp.digit; }));
  pick.push_back(first([](const Copy& cp) { return cp.is_wots && cp.j >= cp.digit; }));
  pick.push_back(first([](const Copy& cp) { return cp.is_acc; }));
  pick.push_back(first([](const Copy& cp) { return cp.cont; }));
  const size_t nc = pick.size();

  using Zk = SlhDsaZk<P, ZkCategory3>;
  auto circuit = Zk::make_circuit(nc);
  auto w = std::make_unique<Dense<Field>>(nc, circuit->ninputs);
  for (size_t c = 0; c < nc; ++c) {
    Zk::fill_public(plan.copies[pick[c]], *w, c, F);
    Zk::fill_private(plan.copies[pick[c]], *w, c, F);
  }

  EvalProver p(F);
  size_t general = 0;
  for (size_t ly = circuit->nl; ly-- > 0;) {
    const Quad<Field>& quad = *circuit->l[ly].quad;
    for (const auto& ec : quad) {
      general += ec.v != F.zero() && ec.v != F.one();
    }
    const corner_t nw = ly > 0 ? circuit->l[ly - 1].nw : circuit->nv;
    auto got = std::make_unique<Dense<Field>>(nc, nw);
    Dense<Field> want(nc, nw);
    ASSERT_TRUE(p.eval(quad, nw, *w, got.get(), F)) << "layer " << ly;
    ASSERT_TRUE(reference_eval(quad, &want, *w, F)) << "layer " << ly;
    ASSERT_EQ(got->v_, want.v_) << "layer " << ly;

    // Wire 0 not one in the last copy: wire 0 is kept in full, so its terms
    // take the other paths, with the same assertion result, and the same
    // values if no assertion fails.
    Dense<Field> other(nc, w->n1_);
    other.v_ = w->v_;
    other.v_[nc - 1] = F.of_scalar(3);
    Dense<Field> got2(nc, nw), want2(nc, nw);
    const bool ok2 = p.eval(quad, nw, other, &got2, F);
    EXPECT_EQ(ok2, reference_eval(quad, &want2, other, F)) << "layer " << ly;
    if (ok2) EXPECT_EQ(got2.v_, want2.v_) << "layer " << ly;

    w = std::move(got);
  }
  // The circuit has terms with other coefficients, so the general path ran.
  EXPECT_GT(general, 0u);
}
#endif

int64_t NsSince(std::chrono::steady_clock::time_point t0) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now() - t0)
      .count();
}

template <class P>
void BM_Combined(benchmark::State& state, Example (*example)()) {
  set_log_level(ERROR);
  const Example ex = example();
  const auto zk = SlhDsaZk<P>::Make(ex.pk, ex.ctx, ex.msg.size());
  check(zk != nullptr, "SLH-DSA statement");
  for (auto _ : state) {
    const auto t0 = std::chrono::steady_clock::now();
    check(zk->Prove(ex.msg, ex.sig), "SLH-DSA proof failed");
    const int64_t prove_ns = NsSince(t0);
    const auto t1 = std::chrono::steady_clock::now();
    check(zk->Verify(), "SLH-DSA proof did not verify");
    const int64_t verify_ns = NsSince(t1);
    state.counters["prove_ns"] = static_cast<double>(prove_ns);
    state.counters["verify_ns"] = static_cast<double>(verify_ns);
    state.counters["proof_bytes"] = static_cast<double>(zk->ProofBytes());
    state.counters["copies"] = static_cast<double>(zk->copies());
  }
}
#if PROOFS_SHAKE256_DIGEST_BYTES == 64
BENCHMARK_CAPTURE(BM_Combined<SlhDsaShake256s>, SLHDSA_SHAKE_256s, Example256s);
BENCHMARK_CAPTURE(BM_Combined<SlhDsaShake256f>, SLHDSA_SHAKE_256f, Example256f);
#else
BENCHMARK_CAPTURE(BM_Combined<SlhDsaShake192s>, SLHDSA_SHAKE_192s, Example192s);
BENCHMARK_CAPTURE(BM_Combined<SlhDsaShake192f>, SLHDSA_SHAKE_192f, Example192f);
#endif

}  // namespace
}  // namespace slh_dsa
}  // namespace proofs
