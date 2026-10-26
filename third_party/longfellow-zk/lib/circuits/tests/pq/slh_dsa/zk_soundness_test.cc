// Soundness tests of the ZK proofs over circuit copies (not upstream;
// zk_common/zk_prover/zk_verifier). A malicious prover (MaliciousZkProver, a
// copy of ZkProver with hooks) proves false statements: it skips its own
// checks and changes proof elements before Fiat-Shamir, so the transcript
// stays consistent and only the verifier's constraints can reject.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "arrays/packed_layer.h"
#include "circuits/compiler/compiler.h"
#include "circuits/tests/pq/slh_dsa/malicious_zk_prover.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_transcript.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_common.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

constexpr size_t kRate = 4;
constexpr size_t kQueries = 32;  // small: tests only check accept/reject

struct GF2Setup {
  using Field = GF2_128<>;
  using RSFactory = LCH14ReedSolomonFactory<Field>;
  Field F;
  RSFactory rsf;
  const char* name = "GF2_128";
  GF2Setup() : F(), rsf(F) {}
};

struct FpSetup {
  using Field = Fp<1>;
  using Conv = FFTConvolutionFactory<Field>;
  using RSFactory = ReedSolomonFactory<Field, Conv>;
  Field F;
  Conv conv;
  RSFactory rsf;
  const char* name = "Fp64";
  FpSetup()
      : F("18446744069414584321"),
        conv(F, F.of_scalar(1753635133440165772ull), 1ull << 32),
        rsf(conv, F) {}
};

// Inputs: 0 = one, 1 = a (public); private: 2 = x, 3 = y, 4 = z.
// Asserts y = a*x + x and z = (y*y) * (x*a).
constexpr size_t kNpub = 2, kNin = 6;

template <class Field>
std::unique_ptr<Circuit<Field>> make_circuit(const Field& F, size_t nc) {
  QuadCircuit<Field> Q(F);
  size_t a = Q.input_wire();
  Q.private_input();
  size_t x = Q.input_wire();
  size_t y = Q.input_wire();
  size_t z = Q.input_wire();
  size_t u = Q.input_wire();
  Q.assert0(Q.sub(y, Q.add(Q.mul(a, x), Q.linear(x))));
  Q.assert0(Q.sub(z, Q.mul(Q.mul(y, y), Q.mul(x, a))));
  size_t y2 = Q.mul(y, y), y4 = Q.mul(y2, y2), y8 = Q.mul(y4, y4);
  Q.assert0(Q.sub(u, Q.mul(Q.mul(y8, y8), Q.add(a, x))));
  auto c = Q.mkcircuit(nc);
  check(c->ninputs == kNin && c->npub_in == kNpub, "layout");
  return c;
}

template <class Field>
struct Inst {
  using Elt = typename Field::Elt;
  std::vector<Elt> a, x, y, z, u;
};

template <class Field>
Inst<Field> make_inst(const Field& F, size_t nc) {
  Inst<Field> in;
  SecureRandomEngine rng;
  for (size_t c = 0; c < nc; ++c) {
    auto a = rng.elt(F), x = rng.elt(F);
    auto y = F.addf(F.mulf(a, x), x);
    auto z = F.mulf(F.mulf(y, y), F.mulf(x, a));
    in.a.push_back(a);
    in.x.push_back(x);
    in.y.push_back(y);
    in.z.push_back(z);
    auto y2 = F.mulf(y, y), y4 = F.mulf(y2, y2), y8 = F.mulf(y4, y4);
    in.u.push_back(F.mulf(F.mulf(y8, y8), F.addf(a, x)));
  }
  return in;
}

template <class Field>
std::unique_ptr<Dense<Field>> fill(const Field& F, const Inst<Field>& in,
                                   bool public_only) {
  const size_t nc = in.a.size();
  auto w = std::make_unique<Dense<Field>>(nc, public_only ? kNpub : kNin);
  for (size_t c = 0; c < nc; ++c) {
    typename Field::Elt v[kNin] = {F.one(), in.a[c], in.x[c], in.y[c],
                                   in.z[c], in.u[c]};
    for (size_t i = 0; i < w->n1_; ++i) w->v_[nc * i + c] = v[i];
  }
  return w;
}

template <class S>
using Extra = typename ZkCommon<typename S::Field>::ExtraConstraints;

template <class S>
struct Run {
  std::unique_ptr<Circuit<typename S::Field>> circuit;
  std::unique_ptr<ZkProof<typename S::Field>> proof;
};

// Proves with the malicious prover; W_COMMIT is committed, W_SUM drives sumcheck.
template <class S>
Run<S> malicious_prove(const S& s, size_t nc, const Dense<typename S::Field>& wc,
                  const Dense<typename S::Field>& ws,
                  const Extra<S>* extra = nullptr, bool* ok = nullptr) {
  Run<S> r;
  r.circuit = make_circuit(s.F, nc);
  r.proof = std::make_unique<ZkProof<typename S::Field>>(*r.circuit, kRate,
                                                         kQueries);
  MaliciousZkProver<typename S::Field, typename S::RSFactory> prover(*r.circuit,
                                                                s.F, s.rsf);
  SecureRandomEngine rng;
  Transcript tp((uint8_t*)"soundness", 9);
  prover.commit(*r.proof, wc, tp, rng);
  bool b = prover.prove(*r.proof, ws, tp, extra);
  if (ok) *ok = b;
  return r;
}

template <class S>
bool verify(const S& s, const Run<S>& r, const Dense<typename S::Field>& pub,
            const Extra<S>* extra = nullptr) {
  // Serialize and re-read, as a real verifier.
  std::vector<uint8_t> buf;
  r.proof->write(buf, s.F);
  ZkProof<typename S::Field> zp(*r.circuit, kRate, kQueries);
  ReadBuffer rb(buf);
  if (!zp.read(rb, s.F)) return false;
  ZkVerifier<typename S::Field, typename S::RSFactory> v(*r.circuit, s.rsf,
                                                         kRate, kQueries, s.F);
  Transcript tv((uint8_t*)"soundness", 9);
  v.recv_commitment(zp, tv);
  return v.verify(zp, pub, tv, extra);
}

template <class S>
void reset_hooks() {
  set_log_level(ERROR);
  using L = MaliciousProverLayers<typename S::Field>;
  L::skip_asserts = false;
  L::override_nc = 0;
  L::tamper_c = nullptr;
  L::tamper_h = nullptr;
  L::tamper_wc = nullptr;
}

const size_t kCopies[] = {1, 2, 3, 5, 8, 13, 31, 64};

template <class S>
void honest(const S& s) {
  reset_hooks<S>();
  for (size_t nc : kCopies) {
    auto in = make_inst(s.F, nc);
    auto w = fill(s.F, in, false);
    auto pub = fill(s.F, in, true);
    auto r = malicious_prove(s, nc, *w, *w);
    EXPECT_TRUE(verify(s, r, *pub)) << s.name << " nc=" << nc;
  }
}
TEST(ZkSoundness, HonestGF2) {
  const GF2Setup s;
  honest(s);
}
TEST(ZkSoundness, HonestFp) {
  const FpSetup s;
  honest(s);
}

// One copy violates an assertion; the prover skips its own checks.
template <class S>
void false_copy(const S& s) {
  reset_hooks<S>();
  MaliciousProverLayers<typename S::Field>::skip_asserts = true;
  for (size_t nc : kCopies) {
    for (size_t bad : {size_t(0), nc / 2, nc - 1}) {
      for (int which : {0, 1, 2}) {
        auto in = make_inst(s.F, nc);
        if (which == 0) {
          s.F.add(in.y[bad], s.F.one());  // breaks assertion 1 (and 2)
        } else if (which == 1) {
          s.F.add(in.z[bad], s.F.one());  // breaks assertion 2 only
        } else {
          s.F.add(in.u[bad], s.F.one());  // breaks the deep assertion only
        }
        auto w = fill(s.F, in, false);
        auto pub = fill(s.F, in, true);
        bool ok = false;
        auto r = malicious_prove(s, nc, *w, *w, nullptr, &ok);
        ASSERT_TRUE(ok);
        EXPECT_FALSE(verify(s, r, *pub))
            << s.name << " nc=" << nc << " bad=" << bad << " which=" << which;
      }
    }
  }
  reset_hooks<S>();
}
TEST(ZkSoundness, FalseCopyGF2) {
  const GF2Setup s;
  false_copy(s);
}
TEST(ZkSoundness, FalseCopyFp) {
  const FpSetup s;
  false_copy(s);
}

// Tamper each sent proof element before it enters the transcript; the
// Ligero proof is then made over the constraints of the tampered proof. An
// element whose pad is not constrained would be accepted.
template <class S>
void tamper_all(const S& s) {
  using Field = typename S::Field;
  using L = MaliciousProverLayers<Field>;
  for (size_t nc : {size_t(3), size_t(8)}) {
    auto in = make_inst(s.F, nc);
    auto w = fill(s.F, in, false);
    auto pub = fill(s.F, in, true);
    auto circuit = make_circuit(s.F, nc);
    size_t cases = 0;
    for (size_t ly = 0; ly < circuit->nl; ++ly) {
      for (size_t round = 0; round < circuit->logc; ++round) {
        for (size_t k = 0; k < 4; ++k) {
          reset_hooks<S>();
          L::tamper_c = [&](size_t l, size_t rd, typename L::HookC& p) {
            if (l == ly && rd == round) s.F.add(p.t_[k], s.F.one());
          };
          auto r = malicious_prove(s, nc, *w, *w);
          // t_[1] is not part of the proof (implied), so it must not matter.
          EXPECT_EQ(verify(s, r, *pub), k == 1)
              << s.name << " cp nc=" << nc << " ly=" << ly << " round="
              << round << " k=" << k;
          ++cases;
        }
      }
      for (size_t round = 0; round < circuit->l[ly].logw; ++round) {
        for (size_t hand = 0; hand < 2; ++hand) {
          for (size_t k = 0; k < 3; ++k) {
            reset_hooks<S>();
            L::tamper_h = [&](size_t l, size_t h, size_t rd,
                              typename L::HookW& p) {
              if (l == ly && h == hand && rd == round) {
                s.F.add(p.t_[k], s.F.one());
              }
            };
            auto r = malicious_prove(s, nc, *w, *w);
            EXPECT_EQ(verify(s, r, *pub), k == 1)
                << s.name << " hp nc=" << nc << " ly=" << ly << " round="
                << round << " hand=" << hand << " k=" << k;
            ++cases;
          }
        }
      }
      for (size_t k = 0; k < 2; ++k) {
        reset_hooks<S>();
        L::tamper_wc = [&](size_t l, typename Field::Elt* tt) {
          if (l == ly) s.F.add(tt[k], s.F.one());
        };
        auto r = malicious_prove(s, nc, *w, *w);
        EXPECT_FALSE(verify(s, r, *pub))
            << s.name << " wc nc=" << nc << " ly=" << ly << " k=" << k;
        ++cases;
      }
    }
    printf("%s nc=%zu nl=%zu logc=%zu: %zu tamper cases\n", s.name, nc,
           circuit->nl, circuit->logc, cases);
  }
  reset_hooks<S>();
}
TEST(ZkSoundness, TamperAllGF2) {
  const GF2Setup s;
  tamper_all(s);
}
TEST(ZkSoundness, TamperAllFp) {
  const FpSetup s;
  tamper_all(s);
}

// Every committed column (witness and pad) has a nonzero coefficient in
// some linear constraint, or is a quadratic-constraint operand.
template <class S>
void coverage(const S& s) {
  using Field = typename S::Field;
  reset_hooks<S>();
  for (size_t nc : kCopies) {
    auto in = make_inst(s.F, nc);
    auto w = fill(s.F, in, false);
    auto pub = fill(s.F, in, true);
    auto r = malicious_prove(s, nc, *w, *w);
    const size_t nw = ZkCommon<Field>::num_witness(*r.circuit);
    const size_t np = ZkCommon<Field>::pad_size(*r.circuit);
    std::vector<LigeroLinearConstraint<Field>> a;
    std::vector<typename Field::Elt> b;
    LigeroProductRow<Field> row;
    Transcript tv((uint8_t*)"soundness", 9);
    LigeroVerifier<Field, typename S::RSFactory>::receive_commitment(
        r.proof->com, tv);
    ZkCommon<Field>::initialize_sumcheck_fiat_shamir(tv, *r.circuit, *pub,
                                                     s.F);
    size_t cn = ZkCommon<Field>::verifier_constraints(
        *r.circuit, *pub, r.proof->proof, nullptr, a, b, row, tv, nw, s.F);
    EXPECT_EQ(cn, r.circuit->nl + 1);
    EXPECT_EQ(b.size(), cn);
    std::vector<int> used(nw + np, 0);
    for (const auto& t : a) {
      ASSERT_LT(t.w, nw + np);
      ASSERT_LT(t.c, cn);
      if (t.k != s.F.zero()) used[t.w] = 1;
    }
    ASSERT_LT(row.c, cn);
    ASSERT_LE(row.first + row.u.size() * row.v.size(), nw + np);
    for (size_t i = 0; i < row.u.size(); ++i) {
      for (size_t j = 0; j < row.v.size(); ++j) {
        if (row.u[i] != s.F.zero() && row.v[j] != s.F.zero()) {
          used[row.first + i * row.v.size() + j] = 1;
        }
      }
    }
    std::vector<LigeroQuadraticConstraint> lqc(r.circuit->nl);
    ZkCommon<Field>::setup_lqc(*r.circuit, lqc, nw);
    size_t unused = 0;
    for (size_t i = 0; i < nw + np; ++i) {
      if (!used[i]) {
        bool in_q = false;
        for (auto& q : lqc) in_q |= (q.z == i);
        if (!in_q) {
          ++unused;
          ADD_FAILURE() << s.name << " nc=" << nc << " column " << i
                        << " unconstrained (nw=" << nw << ")";
        }
      }
    }
    EXPECT_EQ(unused, 0u);
  }
}
TEST(ZkSoundness, CoverageGF2) {
  const GF2Setup s;
  coverage(s);
}
TEST(ZkSoundness, CoverageFp) {
  const FpSetup s;
  coverage(s);
}

// Public inputs: copies permuted, or in a copy-major layout, must fail.
template <class S>
void pub_layout(const S& s) {
  reset_hooks<S>();
  for (size_t nc : {size_t(2), size_t(3), size_t(5)}) {
    auto in = make_inst(s.F, nc);
    auto w = fill(s.F, in, false);
    auto r = malicious_prove(s, nc, *w, *w);
    Inst<typename S::Field> sw = in;
    std::swap(sw.a[0], sw.a[1]);
    EXPECT_FALSE(verify(s, r, *fill(s.F, sw, true))) << s.name << nc;
    auto pub = fill(s.F, in, true);
    Dense<typename S::Field> t(nc, kNpub);
    for (size_t c = 0; c < nc; ++c) {
      for (size_t i = 0; i < kNpub; ++i) t.v_[kNpub * c + i] = pub->v_[nc * i + c];
    }
    EXPECT_FALSE(verify(s, r, t)) << s.name << nc;
  }
}
TEST(ZkSoundness, PubLayoutGF2) {
  const GF2Setup s;
  pub_layout(s);
}
TEST(ZkSoundness, PubLayoutFp) {
  const FpSetup s;
  pub_layout(s);
}

// Commit with copies 0 and 1 of the private inputs swapped; sumcheck on the
// true witness. Also: commit valid but run sumcheck on a witness with a
// failing copy 2 (asserts skipped).
template <class S>
void commit_mismatch(const S& s) {
  reset_hooks<S>();
  const size_t nc = 5;
  auto in = make_inst(s.F, nc);
  auto w = fill(s.F, in, false);
  auto pub = fill(s.F, in, true);
  Inst<typename S::Field> sw = in;
  std::swap(sw.x[0], sw.x[1]);
  std::swap(sw.y[0], sw.y[1]);
  std::swap(sw.z[0], sw.z[1]);
  std::swap(sw.u[0], sw.u[1]);
  auto ws = fill(s.F, sw, false);
  auto r = malicious_prove(s, nc, *ws, *w);
  EXPECT_FALSE(verify(s, r, *pub)) << s.name;

  MaliciousProverLayers<typename S::Field>::skip_asserts = true;
  Inst<typename S::Field> bad = in;
  s.F.add(bad.z[2], s.F.one());
  auto wb = fill(s.F, bad, false);
  auto r2 = malicious_prove(s, nc, *w, *wb);
  EXPECT_FALSE(verify(s, r2, *pub)) << s.name;
  reset_hooks<S>();
}
TEST(ZkSoundness, CommitMismatchGF2) {
  const GF2Setup s;
  commit_mismatch(s);
}
TEST(ZkSoundness, CommitMismatchFp) {
  const FpSetup s;
  commit_mismatch(s);
}

// The extra constraints are bound into the transcript (extra_hash): a prover
// that may pick b cannot change it after seeing the Ligero challenge alphal.
// Honest witness, extra rows x[0] = b0, x[1] = b1; b' != b with
// alphal . (b' - b) = 0 for the transcript of b is rejected, because b'
// gives another transcript.
template <class S>
void extra_rhs_bound(const S& s) {
  using Field = typename S::Field;
  using Elt = typename Field::Elt;
  using Llc = LigeroLinearConstraint<Field>;
  reset_hooks<S>();
  const size_t nc = 3;
  auto in = make_inst(s.F, nc);
  auto w = fill(s.F, in, false);
  auto pub = fill(s.F, in, true);
  auto circuit = make_circuit(s.F, nc);
  Extra<S> e;
  e.a.push_back(LigeroUnitTerm{uint32_t(0), uint32_t(ZkCommon<Field>::witness_index(*circuit, 2, 0)), false});
  e.a.push_back(LigeroUnitTerm{uint32_t(1), uint32_t(ZkCommon<Field>::witness_index(*circuit, 2, 1)), false});
  e.b = {in.x[0], in.x[1]};
  auto r = malicious_prove(s, nc, *w, *w, &e);
  ASSERT_TRUE(verify(s, r, *pub, &e));

  // Replay the verifier transcript to learn alphal.
  const size_t nw = ZkCommon<Field>::num_witness(*r.circuit);
  LigeroParam<Field> param(nw + ZkCommon<Field>::pad_size(*r.circuit),
                           r.circuit->nl, kRate, kQueries);
  Transcript tv((uint8_t*)"soundness", 9);
  LigeroVerifier<Field, typename S::RSFactory>::receive_commitment(
      r.proof->com, tv);
  ZkCommon<Field>::initialize_sumcheck_fiat_shamir(tv, *r.circuit, *pub, s.F);
  std::vector<Llc> a;
  std::vector<Elt> b;
  LigeroProductRow<Field> row;
  size_t cn = ZkCommon<Field>::verifier_constraints(
      *r.circuit, *pub, r.proof->proof, nullptr, a, b, row, tv, nw, s.F);
  const size_t nl = cn + 2;
  const LigeroHash hash = ZkCommon<Field>::extra_hash(e, s.F);
  tv.write(hash.bytes, hash.kLength);
  std::vector<Elt> uldt(param.nwqrow), alphal(nl);
  LigeroTranscript<Field>::gen_uldt(&uldt[0], param, tv, s.F);
  LigeroTranscript<Field>::gen_alphal(nl, &alphal[0], tv, s.F);
  // b0' = b0 + d0, b1' = b1 - d0 * alphal0 / alphal1.
  Elt d0 = s.F.one();
  Extra<S> forged = e;
  s.F.add(forged.b[0], d0);
  s.F.sub(forged.b[1],
          s.F.mulf(d0, s.F.mulf(alphal[cn], s.F.invertf(alphal[cn + 1]))));
  EXPECT_NE(forged.b[0], in.x[0]);
  EXPECT_FALSE(verify(s, r, *pub, &forged));
}
TEST(ZkSoundness, ExtraRhsBoundGF2) {
  const GF2Setup s;
  extra_rhs_bound(s);
}
TEST(ZkSoundness, ExtraRhsBoundFp) {
  const FpSetup s;
  extra_rhs_bound(s);
}

// nc not a power of two: the prover evaluates and runs sumcheck over all
// 2^logc copies, with chosen values in the padding copies nc..2^logc-1
// (EQ zeroed there, as the verifier's truncated EQ). The commitment holds
// the nc real copies.
template <class S>
void padding_copies(const S& s) {
  using Field = typename S::Field;
  using L = MaliciousProverLayers<Field>;
  for (size_t nc : {size_t(3), size_t(5), size_t(13)}) {
    size_t n2 = 1;
    while (n2 < nc) n2 *= 2;
    for (int mode : {0, 1, 2, 3}) {
      reset_hooks<S>();
      L::override_nc = n2;
      L::skip_asserts = true;
      auto full = make_inst(s.F, n2);  // valid instances for all n2 copies
      if (mode == 2 || mode == 3) s.F.add(full.u[nc - 1], s.F.one());
      auto wfull = fill(s.F, full, false);
      if (mode == 0 || mode == 2) {
        // zero padding copies (mode 0: honest-equivalent)
        for (size_t i = 0; i < kNin; ++i) {
          for (size_t c = nc; c < n2; ++c) wfull->v_[n2 * i + c] = s.F.zero();
        }
      } else if (mode == 3) {
        // padding copy nc carries the negated error of copy nc-1
        for (size_t c = nc; c < n2; ++c) wfull->v_[n2 * 5 + c] = s.F.zero();
        s.F.sub(wfull->v_[n2 * 5 + nc], s.F.one());
      }
      Inst<Field> real = full;
      real.a.resize(nc);
      real.x.resize(nc);
      real.y.resize(nc);
      real.z.resize(nc);
      real.u.resize(nc);
      auto wreal = fill(s.F, real, false);
      auto pub = fill(s.F, real, true);
      bool ok = false;
      auto r = malicious_prove(s, nc, *wreal, *wfull, nullptr, &ok);
      ASSERT_TRUE(ok);
      bool v = verify(s, r, *pub);
      printf("%s nc=%zu n2=%zu mode=%d accepted=%d\n", s.name, nc, n2, mode,
             v);
      // mode 0 is an honest proof; mode 1 is a true statement with junk
      // padding; modes 2, 3 are false statements.
      if (mode == 0) EXPECT_TRUE(v);
      if (mode >= 2) EXPECT_FALSE(v);
    }
  }
  reset_hooks<S>();
}
// ZkProver (packed inputs read in place, evaluation by output wire, packed
// first copy round) gives, for the same randomness, the proof of
// MaliciousZkProver without attacks, which keeps upstream's structure (Dense
// inputs, eval_circuit, prove), byte for byte.
template <class S>
void same_proof_as_dense(const S& s) {
  using Field = typename S::Field;
  for (size_t nc : {1, 3, 64, 65}) {
    auto in = make_inst(s.F, nc);
    auto w = fill(s.F, in, false);
    auto circuit = make_circuit(s.F, nc);
    std::vector<uint8_t> bytes[2];
    for (int k = 0; k < 2; ++k) {
      ZkProof<Field> proof(*circuit, kRate, kQueries);
      Transcript rng((uint8_t*)"rng", 3);
      Transcript tp((uint8_t*)"soundness", 9);
      if (k == 0) {
        ZkProver<Field, typename S::RSFactory> prover(*circuit, s.F, s.rsf);
        const PackedLayer<Field> packed(*w, s.F);
        prover.commit(proof, packed, tp, rng);
        ASSERT_TRUE(prover.prove(proof, packed, tp));
      } else {
        MaliciousZkProver<Field, typename S::RSFactory> prover(*circuit, s.F,
                                                               s.rsf);
        prover.commit(proof, *w, tp, rng);
        ASSERT_TRUE(prover.prove(proof, *w, tp, nullptr));
      }
      proof.write(bytes[k], s.F);
    }
    EXPECT_EQ(bytes[0], bytes[1]) << "nc = " << nc;
  }
}
TEST(ZkSoundness, SameProofAsDenseGF2) {
  const GF2Setup s;
  same_proof_as_dense(s);
}
TEST(ZkSoundness, SameProofAsDenseFp) {
  const FpSetup s;
  same_proof_as_dense(s);
}

TEST(ZkSoundness, PaddingCopiesGF2) {
  const GF2Setup s;
  padding_copies(s);
}
TEST(ZkSoundness, PaddingCopiesFp) {
  const FpSetup s;
  padding_copies(s);
}

}  // namespace
}  // namespace proofs
