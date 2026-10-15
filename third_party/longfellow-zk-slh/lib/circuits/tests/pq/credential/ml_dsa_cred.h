// The post-quantum credential proof with ML-DSA signatures (not upstream).
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!  Experimental research code.
//
// Statement, over Fq^12 (q = 8380417), for one presentation of the
// credential of credential.h:
//
//   - the issuer signature on D verifies under the public issuer key;
//   - BIRTH <= MAX_BIRTH and VALID_FROM <= NOW <= VALID_UNTIL (age.h);
//   - without CFT: a signature on the public NONCE verifies under a private
//     hardware key whose ID (tr) is in attributes 14 and 15;
//   - with CFT: the public C4 signature on SHAKE256(T || R2) verifies under
//     a private user key whose ID is in attributes 0 and 1, and the public
//     (U, V) encrypts ID || R2 (lwe.h; T public, R2 private).
//
// A private key is verified with its matrix A computed in the circuit
// (ExpandA, FIPS 204 Alg. 32) and its tr = SHAKE256(pk) hashed in the
// circuit. Parts of the proof (zk/zk_multi.h):
//
//   0  sponge: every SHAKE call outside the verifications (sponge.h)
//   1  verify: two copies of the ML-DSA verification on mu (issuer, user),
//      with A, t1 and mu private (the issuer's fixed to constants)
//   2  rej: one copy per polynomial of the user's A (RejNTTPoly, Alg. 30)
//   3  age: the timestamp checks
//   4  lwe: the encryption (with CFT only)

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_ML_DSA_CRED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_ML_DSA_CRED_H_

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <vector>

#include "algebra/fp24.h"
#include "algebra/fp24_ext.h"
#include "arrays/dense.h"
#include "arrays/packed_layer.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/credential/age.h"
#include "circuits/tests/pq/credential/credential.h"
#include "circuits/tests/pq/credential/lwe.h"
#include "circuits/tests/pq/credential/sponge.h"
#include "circuits/tests/pq/credential/statement.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_circuit.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_witness.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_zk_harness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/crypto.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_multi.h"
#include "zk/zk_soundness.h"

namespace proofs {
namespace pq_cred {

// RejNTTPoly (FIPS 204, Algorithm 30) from 840 bytes of SHAKE128 output (5
// blocks): 280 candidates z = b0 + 2^8 b1 + 2^16 (b2 mod 128), accepted if
// z < q. Output j is the candidate at s_j = j + d_j, with d_j in [0, 32)
// private (5 bits): the circuit checks that candidate s_j is accepted and
// that d_j candidates before it are rejected, so s_j is the position of the
// j-th accepted candidate. As RejNTTPoly in ml_dsa_ref.cc with 5 blocks,
// the prover fails if fewer than 256 of the 280 candidates are accepted
// (25 rejections at rate 2^-10: about 2^-130 per polynomial); otherwise at
// most 24 rejections precede an output and the window always suffices.
template <class LogicCircuit>
class RejPolyCircuit {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using v23 = typename LogicCircuit::template bitvec<23>;
  using v5 = typename LogicCircuit::template bitvec<5>;

 public:
  static constexpr size_t kCand = 280;
  static constexpr size_t kWindow = 32;
  // Private input offsets, from the first private input.
  static constexpr size_t kCandOff = 0;
  static constexpr size_t kSelOff = kCandOff + 23 * kCand;
  static constexpr size_t kCoefOff = kSelOff + 5 * ml_dsa::N;
  static constexpr size_t kNPriv = kCoefOff + ml_dsa::N;

  struct Private {
    std::array<v23, kCand> cand;
    std::array<v5, ml_dsa::N> sel;
    std::array<EltW, ml_dsa::N> coef;
    void input(const LogicCircuit& lc) {
      for (auto& x : cand) x = lc.template vinput<23>();
      for (auto& x : sel) x = lc.template vinput<5>();
      for (auto& x : coef) x = lc.eltw_input();
    }
  };

  explicit RejPolyCircuit(const LogicCircuit& lc) : lc_(lc) {}

  void assert_poly(const Private& w) const {
    constexpr size_t kAll = ml_dsa::N + kWindow - 1;
    static_assert(kAll >= kCand, "candidates fit the windows");
    std::vector<EltW> c(kAll), r(kAll), d(kAll);
    EltW acc = lc_.konst(lc_.f_.zero());
    for (size_t k = 0; k < kAll; ++k) {
      if (k < kCand) {
        const v23& x = w.cand[k];
        // sum 2^b x_b, which wraps modulo q for a rejected candidate
        // (Logic::as_scalar requires 2^23 - 1 < q).
        c[k] = lc_.konst(lc_.f_.zero());
        for (size_t b = 0; b < 23; ++b) {
          c[k] = lc_.axpy(c[k], lc_.f_.of_scalar(uint64_t(1) << b),
                          lc_.eval(x[b]));
        }
        // z >= q = 2^23 - 2^13 + 1 iff bits 13-22 are all one and bits
        // 0-12 are not all zero.
        BitW hi = x[13];
        for (size_t b = 14; b < 23; ++b) hi = lc_.land(hi, x[b]);
        BitW lo_zero = lc_.lnot(x[0]);
        for (size_t b = 1; b < 13; ++b) lo_zero = lc_.land(lo_zero, lc_.lnot(x[b]));
        r[k] = lc_.eval(lc_.land(hi, lc_.lnot(lo_zero)));
      } else {
        c[k] = lc_.konst(lc_.f_.zero());
        r[k] = lc_.konst(lc_.f_.one());
      }
      acc = lc_.add(acc, r[k]);
      d[k] = acc;  // rejected candidates in [0, k]
    }
    for (size_t j = 0; j < ml_dsa::N; ++j) {
      lc_.assert0(select(w.sel[j], &r[j]));
      lc_.assert_eq(select(w.sel[j], &d[j]), lc_.as_scalar(w.sel[j]));
      lc_.assert_eq(w.coef[j], select(w.sel[j], &c[j]));
    }
  }

  // Native witness from the 840 SHAKE128 bytes; false if a window is too
  // short.
  static bool witness(const std::vector<uint8_t>& out,
                      std::array<uint32_t, kCand>& cand,
                      std::array<uint8_t, ml_dsa::N>& sel,
                      std::array<uint32_t, ml_dsa::N>& coef) {
    check(out.size() == 3 * kCand, "RejNTTPoly input");
    size_t j = 0;
    for (size_t k = 0; k < kCand; ++k) {
      cand[k] = out[3 * k] | (uint32_t(out[3 * k + 1]) << 8) |
                (uint32_t(out[3 * k + 2] & 0x7F) << 16);
      if (cand[k] < ml_dsa::Q && j < ml_dsa::N) {
        if (k - j >= kWindow) return false;
        sel[j] = static_cast<uint8_t>(k - j);
        coef[j] = cand[k];
        ++j;
      }
    }
    return j == ml_dsa::N;
  }

 private:
  // V[d] for d = SEL (LSB first), from V[0, 32).
  EltW select(const v5& sel, const EltW* v) const {
    std::array<EltW, kWindow> a;
    for (size_t i = 0; i < kWindow; ++i) a[i] = v[i];
    for (size_t t = 0; t < 5; ++t) {
      for (size_t i = 0; i < (kWindow >> (t + 1)); ++i) {
        a[i] = lc_.mux(sel[t], a[2 * i + 1], a[2 * i]);
      }
    }
    return a[0];
  }

  const LogicCircuit& lc_;
};

// ML-DSA verification on mu (ml_dsa_circuit.h) with every input private,
// and NTT(t1 2^13) computed from the bits of t1 (10 per coefficient).
// The inputs are those of MlDsaZkHarness, then t1 and mu.
template <class LogicCircuit, class Field, class Params>
class KeyVerifyCircuit {
  using V = MLDSAVerify<LogicCircuit, Field, Params>;
  using v8 = typename LogicCircuit::v8;
  using v10 = typename LogicCircuit::template bitvec<10>;

 public:
  static constexpr size_t kN = ml_dsa::N;
  static constexpr size_t kCPrimeTildeBlocks =
      (64 + Params::K * Params::w1_bytes + 136) / 136;
  // Private input offsets, from the first private input.
  static constexpr size_t kAHat = 0;
  static constexpr size_t kNttT1 = kAHat + Params::K * Params::L * kN;
  static constexpr size_t kTr = kNttT1 + Params::K * kN;
  static constexpr size_t kCTilde = kTr + 8 * 64;
  static constexpr size_t kZ = kCTilde + 8 * Params::c_tilde_bytes;
  static constexpr size_t kZBits = kZ + Params::L * kN;
  static constexpr size_t kH = kZBits + Params::L * kN * Params::z_bits;
  static constexpr size_t kT1Bits = 10 * Params::K * kN;
  static constexpr size_t kMuBits = 8 * 64;

  struct Private {
    typename V::Pk pk;
    typename V::SignatureW sig;
    typename V::Witness w;
    std::array<std::array<v10, kN>, Params::K> t1;
    std::array<v8, 64> mu;
    void input(const LogicCircuit& lc) {
      pk.input(lc);
      sig.input(lc);
      w.c_prime_tilde_bws_.resize(kCPrimeTildeBlocks);
      w.input(lc);
      for (auto& p : t1) for (auto& x : p) x = lc.template vinput<10>();
      for (auto& x : mu) x = lc.template vinput<8>();
    }
  };

  explicit KeyVerifyCircuit(const LogicCircuit& lc) : lc_(lc) {}

  void assert_valid(const Private& p) const {
    const V verify(lc_);
    const auto scale = lc_.f_.of_scalar(uint64_t(1) << ml_dsa::D);
    for (size_t i = 0; i < Params::K; ++i) {
      typename V::RqW t1s;
      for (size_t c = 0; c < kN; ++c) {
        t1s.coeffs[c] = lc_.mul(scale, lc_.as_scalar(p.t1[i][c]));
      }
      verify.assert_ntt(t1s, p.pk.nttt1[i]);
    }
    verify.assert_valid_signature_on_mu(p.pk, p.sig, p.mu, p.w);
  }

  // The private inputs of one copy, for PK, SIG and MSG (empty context),
  // after the constant one; false if the signature does not verify.
  static bool witness(const std::vector<uint8_t>& pk,
                      const std::vector<uint8_t>& sig,
                      const std::vector<uint8_t>& msg, Dense<Field>& d,
                      const Field& f) {
    const auto wit = std::make_unique<ml_dsa_witness<Params>>();
    if (!wit->compute_witness(pk, sig, msg, {})) return false;
    DenseFiller<Field> filler(d);
    filler.push_back(f.one());
    wit->fill_witness(filler, f);
    for (const auto& p : wit->ref_pk_.t1) {
      for (const auto& x : p) filler.push_back(from_elt(x), 10, f);
    }
    for (uint8_t b : wit->mu_) filler.push_back(b, 8, f);
    check(filler.size() == d.n1_, "verification inputs");
    return true;
  }

 private:
  const LogicCircuit& lc_;
};

// Proof parameters per NIST category: the field and digests of
// MlDsaZkHarness, Ligero queries for the larger tableau (the proximity
// term gives about 0.68 bits per query at rate 4; pq_credential_test
// checks the bound), and the provisional LWE parameters.
template <class Params>
struct MlDsaCredParams {
  using Z = MlDsaZkDefault<Params>;
  static constexpr size_t kQueries = Params::K == 8 ? 380 : 285;
  using LP = std::conditional_t<Params::K == 8, LweCategory5, LweCategory3>;
};

template <class Params, bool kCft>
class MlDsaCredential {
 public:
  using Z = typename MlDsaCredParams<Params>::Z;
  using LP = typename MlDsaCredParams<Params>::LP;
  using Field = typename Z::Field;
  static_assert(kHashDigestSize == Z::kDigestBytes,
                "build with PROOFS_SHAKE256_DIGEST_BYTES = Z::kDigestBytes");

 private:
  using Elt = typename Field::Elt;
  using LC = Logic<Field, CompilerBackend<Field>>;
  using Rej = RejPolyCircuit<LC>;
  using KV = KeyVerifyCircuit<LC, Field, Params>;
  using Lwec = LweCircuit<LC, LP>;
  using RS = typename MlDsaRs<Field>::Factory;
  static constexpr size_t kRate = 4;
  static constexpr size_t kQueries = MlDsaCredParams<Params>::kQueries;
  static constexpr size_t kN = ml_dsa::N;
  static constexpr size_t kPolys = Params::K * Params::L;
  static constexpr size_t kPkBytes = 32 + 320 * Params::K;
  enum Part : uint32_t { kSponge, kVerify, kRej, kAge, kLwe };

 public:
  // The public inputs of one presentation.
  struct Show {
    std::vector<uint8_t> issuer_pk;
    uint64_t now = 0, max_birth = 0;
    std::array<uint8_t, 32> nonce{};  // without CFT
    std::array<uint8_t, 32> t{};      // with CFT
    std::vector<uint8_t> c4;          // with CFT
    LweCiphertext<LP> ct{};           // with CFT
  };

  // The holder's private inputs.
  struct Secret {
    Credential cred;
    Timestamps ts{};
    std::vector<uint8_t> issuer_sig;
    std::vector<uint8_t> user_pk;
    std::vector<uint8_t> user_sig;  // on the nonce, or C4
    std::array<uint8_t, 32> r2{};   // with CFT
    LweRandomness<LP> rnd{};        // with CFT
  };

  explicit MlDsaCredential(const LwePublic<LP>& lwe) : lwe_(lwe) {
    verify_ = make_verify();
    rej_ = make_rej();
    age_ = make_age();
    // The sponge copies do not depend on the inputs: count them on zeros.
    Show show;
    show.issuer_pk.assign(kPkBytes, 0);
    show.c4.assign(sig_bytes(), 0);
    Built b(f_);
    build(show, nullptr, b);
    sponge_ = make_sponge(b.sponge.copies().size());
    std::vector<const Circuit<Field>*> parts = {sponge_.get(), verify_.get(),
                                                rej_.get(), age_.get()};
    if (kCft) {
      lwec_ = make_lwe();
      parts.push_back(lwec_.get());
    }
    // Every wire value lies in Fq, so the full wires of the stored layers
    // take 4 bytes (PackedLayer): no checkpointing.
    lay_ = std::make_unique<ZkMultiLayout<Field>>(
        parts, std::vector<size_t>(parts.size(), 1));
  }

  static constexpr size_t sig_bytes() {
    return Params::c_tilde_bytes +
           Params::L * 32 * (1 + ml_dsa::bitlen(Params::gamma_1 - 1)) +
           Params::omega + Params::K;
  }

  size_t sponge_copies() const { return sponge_->nc; }
  const ZkMultiLayout<Field>& layout() const { return *lay_; }

  // Commits and proves; false if a signature does not verify natively or a
  // RejNTTPoly window is too short.
  bool Prove(const Show& show, const Secret& sec) {
    Built b(f_);
    build(show, &sec, b);
    const auto extra = b.links.resolve(*lay_);

    std::vector<std::unique_ptr<PackedLayer<Field>>> w;
    w.push_back(fill_sponge(b, false));
    auto v = fill_verify(show, sec, b);
    if (v == nullptr) return false;
    w.push_back(std::move(v));
    auto r = fill_rej(b);
    if (r == nullptr) return false;
    w.push_back(std::move(r));
    w.push_back(std::make_unique<PackedLayer<Field>>(1, age_->ninputs, f_));
    Timestamps ts = sec.ts;
    ts.now = show.now;
    ts.max_birth = show.max_birth;
    fill_age(*w.back(), ts, false);
    if (kCft) {
      w.push_back(std::make_unique<PackedLayer<Field>>(1, lwec_->ninputs, f_));
      const auto m = lwe_message(b);
      fill_lwe(*w.back(), f_, show.ct, &m, &sec.rnd);
    }
    std::vector<const PackedLayer<Field>*> wp;
    for (const auto& x : w) wp.push_back(x.get());

    proof_ = std::make_unique<ZkMultiProof<Field>>(*lay_, kRate, kQueries);
    ZkMultiProver<Field, RS> prover(*lay_, f_, rs_.factory);
    Transcript tp((uint8_t*)"pq-credential", 13);
    prover.commit(*proof_, wp, tp, rng_);
    return prover.prove(*proof_, wp, tp, extra);
  }

  // Verifies the serialized proof of the last Prove() against SHOW.
  bool Verify(const Show& show) const {
    std::vector<uint8_t> bytes;
    proof_->write(bytes, f_);
    ZkMultiProof<Field> proof(*lay_, kRate, kQueries);
    ReadBuffer rb(bytes);
    if (!proof.read(rb, f_)) return false;

    Built b(f_);
    build(show, nullptr, b);
    const auto extra = b.links.resolve(*lay_);
    std::vector<std::unique_ptr<PackedLayer<Field>>> pub;
    pub.push_back(fill_sponge(b, true));
    for (const Circuit<Field>* c : {verify_.get(), rej_.get()}) {
      pub.push_back(std::make_unique<PackedLayer<Field>>(c->nc, 1, f_));
      for (size_t k = 0; k < c->nc; ++k) pub.back()->set_bit(0, k, true);
    }
    pub.push_back(
        std::make_unique<PackedLayer<Field>>(1, AgeCircuit<LC>::kNPub, f_));
    Timestamps ts{};
    ts.now = show.now;
    ts.max_birth = show.max_birth;
    fill_age(*pub.back(), ts, true);
    if (kCft) {
      pub.push_back(std::make_unique<PackedLayer<Field>>(1, Lwec::kNPub, f_));
      fill_lwe<Field, LP>(*pub.back(), f_, show.ct, nullptr, nullptr);
    }
    std::vector<const PackedLayer<Field>*> pp;
    for (const auto& x : pub) pp.push_back(x.get());

    ZkMultiVerifier<Field, RS> verifier(*lay_, rs_.factory, kRate,
                                        kQueries, f_);
    Transcript tv((uint8_t*)"pq-credential", 13);
    verifier.recv_commitment(proof, tv);
    return verifier.verify(proof, pp, tv, extra);
  }

  size_t ProofBytes() const {
    std::vector<uint8_t> buf;
    proof_->write(buf, f_);
    return buf.size();
  }

  ZkSoundness Soundness() const {
    std::vector<const Circuit<Field>*> cs;
    for (size_t p = 0; p < lay_->parts(); ++p) cs.push_back(&lay_->circuit(p));
    const ZkMultiProof<Field> proof(*lay_, kRate, kQueries);
    return zk_soundness(cs, proof.param,
                        Z::kDegree * std::log2(double(ml_dsa::Fq().m_)));
  }

 private:
  // The sponge copies and links of a statement, and the references that
  // the other parts link to.
  struct Built {
    explicit Built(const Field& f) : links(f), sponge(kSponge, links) {}
    Links<Field> links;
    Sponge<Field> sponge;
    Bytes pk;   // the user key, references to its definition
    Bytes id;   // tr of the user key
    std::vector<Bytes> expand;  // the 840 SHAKE128 bytes per polynomial
    Bytes issuer_mu, user_mu, r2;
    CredentialRefs cred;
  };

  // The sponge calls and every link. SEC is null for the verifier: the
  // private values are zeros, which change no copy and no link.
  void build(const Show& show, const Secret* sec, Built& b) const {
    Secret zero;
    if (sec == nullptr) {
      zero.user_pk.assign(kPkBytes, 0);
      sec = &zero;
    }
    check(sec->user_pk.size() == kPkBytes && show.issuer_pk.size() == kPkBytes,
          "ML-DSA public key length");
    Sponge<Field>& sp = b.sponge;

    // The user key: tr, and A from rho.
    b.id = sp.shake(kShake256Rate,
                    free_bytes(sec->user_pk.data(), kPkBytes), kIdBytes,
                    &b.pk);
    const Bytes rho = slice(b.pk, 0, 32);
    for (uint8_t r = 0; r < Params::K; ++r) {
      for (uint8_t s = 0; s < Params::L; ++s) {
        const uint8_t sr[2] = {s, r};
        const Bytes idx = const_bytes(sr, 2);
        b.expand.push_back(
            sp.shake(kShake128Rate, cat({&rho, &idx}), 3 * Rej::kCand));
      }
    }

    // The credential and the issuer's mu = SHAKE256(tr || 0 || 0 || D).
    b.cred = hash_credential(sp, sec->cred, b.id, kCft);
    const auto issuer_tr = shake256(show.issuer_pk, 64);
    const uint8_t head[2] = {0, 0};
    const Bytes h = const_bytes(head, 2);
    const Bytes itr = const_bytes(issuer_tr.data(), 64);
    b.issuer_mu =
        sp.shake(kShake256Rate, cat({&itr, &h, &b.cred.digest}), 64);

    // The user's message: the nonce, or the C4 tag SHAKE256(T || R2).
    Bytes msg;
    if (kCft) {
      const Bytes t = const_bytes(show.t.data(), 32);
      const Bytes r2 = free_bytes(sec->r2.data(), 32);
      Bytes in;
      msg = sp.shake(kShake256Rate, cat({&t, &r2}), kHashDigestSize, &in);
      b.r2 = slice(in, 32, 32);
    } else {
      msg = const_bytes(show.nonce.data(), 32);
    }
    b.user_mu = sp.shake(kShake256Rate, cat({&b.id, &h, &msg}), 64);

    link_verify(show, b);
    link_rej(b);
    for (size_t k = 0; k < 3; ++k) {
      const size_t off = k * kTsBits;
      for (size_t t = 0; t < kTsBits; ++t) {
        b.links.bit(Ref{kAge, 0, uint32_t(off + t)}, b.cred.ts[k][t]);
      }
    }
    if (kCft) {
      const Bytes m = cat({&b.id, &b.r2});
      for (size_t i = 0; i < m.size(); ++i) {
        b.links.bit(Ref{kLwe, 0, uint32_t(Lwec::kMsg + i)}, m[i]);
      }
    }
  }

  void link_verify(const Show& show, Built& b) const {
    Links<Field>& l = b.links;
    const size_t npriv = verify_npriv();
    const size_t t1_off = npriv - KV::kMuBits - KV::kT1Bits;
    const size_t mu_off = npriv - KV::kMuBits;
    auto at = [](uint32_t copy, size_t off) {
      return Ref{kVerify, copy, uint32_t(off)};
    };

    // Copy 0: the issuer key, fixed to constants.
    const auto ipk = ml_dsa::pkDecode<Params>(show.issuer_pk);
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t j = 0; j < Params::L; ++j) {
        for (size_t c = 0; c < kN; ++c) {
          l.fixed(at(0, KV::kAHat + (i * Params::L + j) * kN + c),
                  f_.of_scalar(ipk.a_hat[i][j][c]));
        }
      }
      for (size_t c = 0; c < kN; ++c) {
        const uint32_t x = from_elt(ipk.t1[i][c]);
        for (size_t t = 0; t < 10; ++t) {
          l.fixed(at(0, t1_off + 10 * (i * kN + c) + t),
                  (x >> t) & 1 ? f_.one() : f_.zero());
        }
      }
    }
    for (size_t i = 0; i < 8 * 64; ++i) {
      l.bit(at(0, mu_off + i), b.issuer_mu[i]);
    }

    // Copy 1: the user key, A from the rej part, t1 from the hashed key.
    for (size_t p = 0; p < kPolys; ++p) {
      for (size_t c = 0; c < kN; ++c) {
        l.eq(at(1, KV::kAHat + p * kN + c),
             Ref{kRej, uint32_t(p), uint32_t(Rej::kCoefOff + c)});
      }
    }
    for (size_t i = 0; i < KV::kT1Bits; ++i) {
      l.bit(at(1, t1_off + i), b.pk[256 + i]);
    }
    for (size_t i = 0; i < 8 * 64; ++i) l.bit(at(1, mu_off + i), b.user_mu[i]);

    // With CFT, the signature is public: C4.
    if (kCft) {
      const auto sig = ml_dsa::sigDecode<Params>(show.c4);
      check(sig.has_value(), "C4 encoding");
      for (size_t i = 0; i < 8 * Params::c_tilde_bytes; ++i) {
        l.fixed(at(1, KV::kCTilde + i),
                (sig->c_tilde[i / 8] >> (i % 8)) & 1 ? f_.one() : f_.zero());
      }
      for (size_t i = 0; i < Params::L; ++i) {
        for (size_t c = 0; c < kN; ++c) {
          l.fixed(at(1, KV::kZ + i * kN + c), f_.of_scalar(sig->z[i][c]));
        }
      }
      for (size_t i = 0; i < Params::K; ++i) {
        for (size_t c = 0; c < kN; ++c) {
          l.fixed(at(1, KV::kH + i * kN + c),
                  sig->h[i][c] ? f_.one() : f_.zero());
        }
      }
    }
  }

  void link_rej(Built& b) const {
    for (size_t p = 0; p < kPolys; ++p) {
      for (size_t k = 0; k < Rej::kCand; ++k) {
        for (size_t t = 0; t < 23; ++t) {
          b.links.bit(Ref{kRej, uint32_t(p), uint32_t(23 * k + t)},
                      b.expand[p][8 * (3 * k + t / 8) + t % 8]);
        }
      }
    }
  }

  std::array<uint8_t, kLweMsgBytes> lwe_message(const Built& b) const {
    const Bytes m = cat({&b.id, &b.r2});
    std::array<uint8_t, kLweMsgBytes> r{};
    for (size_t i = 0; i < kLweMsgBytes; ++i) r[i] = byte_of(m, i);
    return r;
  }

  size_t verify_npriv() const { return verify_->ninputs - verify_->npub_in; }

  std::unique_ptr<PackedLayer<Field>> fill_sponge(const Built& b,
                                                  bool public_only) const {
    const size_t nc = b.sponge.copies().size();
    check(nc == sponge_->nc, "sponge copies");
    auto w = std::make_unique<PackedLayer<Field>>(
        nc, public_only ? SpongeLayout::npub : sponge_->ninputs, f_);
    for (size_t c = 0; c < nc; ++c) b.sponge.fill(*w, c, public_only);
    return w;
  }

  std::unique_ptr<PackedLayer<Field>> fill_verify(const Show& show,
                                                  const Secret& sec,
                                                  const Built& b) const {
    const size_t n = verify_->ninputs;
    Dense<Field> d(2, n), one(1, n);
    if (!KV::witness(show.issuer_pk, sec.issuer_sig,
                     values(b.cred.digest), one, f_)) {
      return nullptr;
    }
    for (size_t i = 0; i < n; ++i) d.v_[2 * i] = one.v_[i];
    const std::vector<uint8_t> msg =
        kCft ? shake256(cat_bytes(show.t, sec.r2), kHashDigestSize)
             : std::vector<uint8_t>(show.nonce.begin(), show.nonce.end());
    if (!KV::witness(sec.user_pk, sec.user_sig, msg, one, f_)) {
      return nullptr;
    }
    for (size_t i = 0; i < n; ++i) d.v_[2 * i + 1] = one.v_[i];
    return std::make_unique<PackedLayer<Field>>(d, f_);
  }

  static std::vector<uint8_t> cat_bytes(const std::array<uint8_t, 32>& a,
                                        const std::array<uint8_t, 32>& b) {
    std::vector<uint8_t> r(a.begin(), a.end());
    r.insert(r.end(), b.begin(), b.end());
    return r;
  }

  std::unique_ptr<PackedLayer<Field>> fill_rej(const Built& b) const {
    auto w = std::make_unique<PackedLayer<Field>>(kPolys, rej_->ninputs, f_);
    std::vector<Elt> coef(kPolys * kN);
    for (size_t p = 0; p < kPolys; ++p) {
      std::array<uint32_t, Rej::kCand> cand;
      std::array<uint8_t, kN> sel;
      std::array<uint32_t, kN> c;
      if (!Rej::witness(values(b.expand[p]), cand, sel, c)) return nullptr;
      size_t i = 0;
      w->set_bit(i++, p, true);
      for (uint32_t x : cand) {
        for (size_t t = 0; t < 23; ++t) w->set_bit(i++, p, (x >> t) & 1);
      }
      for (uint8_t x : sel) {
        for (size_t t = 0; t < 5; ++t) w->set_bit(i++, p, (x >> t) & 1);
      }
      for (size_t k = 0; k < kN; ++k) coef[k * kPolys + p] = f_.of_scalar(c[k]);
    }
    // The coefficients are full wires, set for all copies at once.
    const size_t first = 1 + Rej::kCoefOff;
    for (size_t k = 0; k < kN; ++k) w->set_wire(first + k, &coef[k * kPolys]);
    return w;
  }

  template <class Body>
  std::unique_ptr<Circuit<Field>> compile(size_t nc, const Body& body) const {
    QuadCircuit<Field> Q(f_);
    const CompilerBackend<Field> cbk(&Q);
    const LC lc(&cbk, f_);
    body(lc, Q);
    return Q.mkcircuit(nc);
  }

  std::unique_ptr<Circuit<Field>> make_sponge(size_t nc) const {
    return compile(nc, [](const LC& lc, QuadCircuit<Field>& Q) {
      typename SpongeStep<LC>::Public u;
      typename SpongeStep<LC>::Private w;
      Sponge<Field>::inputs(lc, Q, u, w);
      Q.begin_full_field();
      SpongeStep<LC>(lc).assert_step(u, w);
    });
  }

  std::unique_ptr<Circuit<Field>> make_verify() const {
    return compile(2, [](const LC& lc, QuadCircuit<Field>& Q) {
      Q.private_input();
      auto p = std::make_unique<typename KV::Private>();
      p->input(lc);
      Q.begin_full_field();
      KV(lc).assert_valid(*p);
    });
  }

  std::unique_ptr<Circuit<Field>> make_rej() const {
    return compile(kPolys, [](const LC& lc, QuadCircuit<Field>& Q) {
      Q.private_input();
      auto w = std::make_unique<typename Rej::Private>();
      w->input(lc);
      Q.begin_full_field();
      Rej(lc).assert_poly(*w);
    });
  }

  std::unique_ptr<Circuit<Field>> make_age() const {
    return compile(1, [](const LC& lc, QuadCircuit<Field>& Q) {
      typename AgeCircuit<LC>::Public u;
      typename AgeCircuit<LC>::Private w;
      u.input(lc);
      Q.private_input();
      w.input(lc);
      Q.begin_full_field();
      AgeCircuit<LC>(lc).assert_valid(u, w);
    });
  }

  std::unique_ptr<Circuit<Field>> make_lwe() const {
    return compile(1, [this](const LC& lc, QuadCircuit<Field>& Q) {
      auto u = std::make_unique<typename Lwec::Public>();
      auto w = std::make_unique<typename Lwec::Private>();
      u->input(lc);
      Q.private_input();
      w->input(lc);
      Q.begin_full_field();
      Lwec(lc, lwe_).assert_encryption(*u, *w);
    });
  }

  const Field f_{ml_dsa::Fq(), 7};
  const MlDsaRs<Field> rs_{ml_dsa::Fq()};
  const LwePublic<LP> lwe_;
  std::unique_ptr<Circuit<Field>> sponge_, verify_, rej_, age_, lwec_;
  std::unique_ptr<ZkMultiLayout<Field>> lay_;
  SecureRandomEngine rng_;
  std::unique_ptr<ZkMultiProof<Field>> proof_;
};

}  // namespace pq_cred
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_ML_DSA_CRED_H_
