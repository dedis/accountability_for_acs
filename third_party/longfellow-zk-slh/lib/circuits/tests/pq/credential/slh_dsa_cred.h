// The post-quantum credential proof with SLH-DSA signatures (not
// upstream).
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!  Experimental research code.
//
// The statement of ml_dsa_cred.h with SLH-DSA (FIPS 205, SHAKE sets): the
// issuer signature on D under the public issuer key, and the signature on
// the nonce (without CFT) or C4 on SHAKE256(T || R2) (with CFT) under a
// private user key (PK.seed, PK.root) whose ID = SHAKE256(PK.seed ||
// PK.root, 64 bytes) is in the credential.
//
// Main proof over GF(2^256) (192s, 192f) or GF(2^384) (256s, 256f):
//
//   0  sponge: ID, the credential, the tag, and (with CFT) the binding
//      H = SHAKE256(ID || R2 || SALT), a public digest
//   1  age: the timestamp checks
//   2+ step: the hash steps of both verifications (slh_dsa.h), the user's
//      key bits linked to the sponge copy that hashes them, in parts of at
//      most kStepChunk copies of the same circuit (the sumcheck buffers of
//      a part grow with its copies): first the general copies (H_msg and
//      the calls of several blocks), then the one-block copies (F and H,
//      slh_dsa::Layout1: no capacity and no output state committed)
//
// With CFT, the encryption is proved over Fq^12, where q is native: a
// second proof with the parts sponge (H again, from private ID, R2 and
// SALT) and lwe (lwe.h). Both proofs compute the public H, so (by the
// collision resistance of SHAKE256) they use the same ID and R2; the
// 32-byte private SALT hides them.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_SLH_DSA_CRED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_SLH_DSA_CRED_H_

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "algebra/fp24.h"
#include "algebra/fp24_ext.h"
#include "arrays/packed_layer.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/circuit_cache.h"
#include "circuits/tests/pq/credential/age.h"
#include "circuits/tests/pq/credential/credential.h"
#include "circuits/tests/pq/credential/lwe.h"
#include "circuits/tests/pq/credential/sponge.h"
#include "circuits/tests/pq/credential/statement.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_zk_harness.h"
#include "circuits/tests/pq/slh_dsa/slh_dsa.h"
#include "circuits/tests/pq/slh_dsa/slh_dsa_zk.h"
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

// Ligero queries at rate 4 for the credential proofs of a category
// (pq_credential_test checks the soundness bounds).
template <bool kCategory5>
constexpr size_t kCredQueries = kCategory5 ? 380 : 285;

template <class P, bool kCft>
class SlhDsaCredential {
  static constexpr bool kCat5 = P::n == 32;
  using Z = slh_dsa::DefaultZk<P>;
  static_assert(kHashDigestSize == Z::kDigestBytes,
                "build with PROOFS_SHAKE256_DIGEST_BYTES = Z::kDigestBytes");

 public:
  using Field = typename Z::Field;       // GF(2^256) or GF(2^384)
  using FieldQ = Fp24Ext<12>;            // the encryption proof
  using LP = std::conditional_t<kCat5, LweCategory5, LweCategory3>;

 private:
  using Elt = typename Field::Elt;
  using LC = Logic<Field, CompilerBackend<Field>>;
  using LCQ = Logic<FieldQ, CompilerBackend<FieldQ>>;
  using Zk = slh_dsa::SlhDsaZk<P, Z>;
  using Lwec = LweCircuit<LCQ, LP>;
  using RS = typename slh_dsa::ZkRs<Field>::Factory;
  using RSQ = typename MlDsaRs<FieldQ>::Factory;
  static constexpr size_t kRate = 4;
  static constexpr size_t kQueries = kCredQueries<kCat5>;
  static constexpr size_t kSaltBytes = 32;
  enum Part : uint32_t { kSponge, kAge, kStep0 };
  static constexpr size_t kStepChunk = 4096;
  enum PartQ : uint32_t { kSpongeQ, kLweQ };

 public:
  struct Show {
    std::vector<uint8_t> issuer_pk;
    uint64_t now = 0, max_birth = 0;
    std::array<uint8_t, 32> nonce{};  // without CFT
    std::array<uint8_t, 32> t{};      // with CFT
    std::vector<uint8_t> c4;          // with CFT
    LweCiphertext<LP> ct{};           // with CFT
    std::vector<uint8_t> h;           // with CFT: SHAKE256(ID || R2 || SALT)
  };

  struct Secret {
    Credential cred;
    Timestamps ts{};
    std::vector<uint8_t> issuer_sig;
    std::vector<uint8_t> user_pk;
    std::vector<uint8_t> user_sig;  // on the nonce (without CFT)
    std::array<uint8_t, 32> r2{};
    std::array<uint8_t, kSaltBytes> salt{};
    LweRandomness<LP> rnd{};
  };

  explicit SlhDsaCredential(const LwePublic<LP>& lwe) : lwe_(lwe), rs_(f_) {
    Show show;
    show.issuer_pk.assign(P::pk_bytes, 0);
    show.c4.assign(P::sig_bytes, 0);
    show.h.assign(kHashDigestSize, 0);
    Built b(f_);
    build(show, nullptr, b);
    nstep_[0] = b.kind[0].size();
    nstep_[1] = b.kind[1].size();
    for (size_t one = 0; one < 2; ++one) {
      auto make = [&](size_t nc) { return Zk::stored_circuit(nc, one); };
      if (nstep_[one] >= kStepChunk) step_full_[one] = make(kStepChunk);
      if (nstep_[one] % kStepChunk != 0) {
        step_last_[one] = make(nstep_[one] % kStepChunk);
      }
    }
    sponge_ = make_sponge<Field, LC>(f_, b.sponge.copies().size());
    age_ = compile<Field, LC>(f_, "age", 1, [](const LC& lc,
                                               QuadCircuit<Field>& Q) {
      typename AgeCircuit<LC>::Public u;
      typename AgeCircuit<LC>::Private w;
      u.input(lc);
      Q.private_input();
      w.input(lc);
      Q.begin_full_field();
      AgeCircuit<LC>(lc).assert_valid(u, w);
    });
    std::vector<const Circuit<Field>*> parts{sponge_.get(), age_.get()};
    for (size_t k = 0; k < step_parts(); ++k) parts.push_back(&step(k));
    // The layers of these binary-field circuits are almost all bits, which
    // are packed: no checkpointing (it would cost time, not save memory).
    lay_ = std::make_unique<ZkMultiLayout<Field>>(
        parts, std::vector<size_t>(parts.size(), 1));
    if (kCft) {
      BuiltQ bq(fq_);
      build_q(show, nullptr, bq);
      sponge_q_ = make_sponge<FieldQ, LCQ>(fq_, bq.sponge.copies().size());
      lwec_ = compile<FieldQ, LCQ>(
          fq_, "lwe_" + object_tag(lwe_), 1,
          [this](const LCQ& lc, QuadCircuit<FieldQ>& Q) {
            auto u = std::make_unique<typename Lwec::Public>();
            auto w = std::make_unique<typename Lwec::Private>();
            u->input(lc);
            Q.private_input();
            w->input(lc);
            Q.begin_full_field();
            Lwec(lc, lwe_).assert_encryption(*u, *w);
          });
      lay_q_ = std::make_unique<ZkMultiLayout<FieldQ>>(
          std::vector<const Circuit<FieldQ>*>{sponge_q_.get(), lwec_.get()});
    }
  }

  size_t step_copies() const { return nstep_[0] + nstep_[1]; }
  size_t sponge_copies() const { return sponge_->nc; }

  // False if a signature does not verify natively.
  bool Prove(const Show& show, const Secret& sec) {
    // The inputs of every part; the statement is freed once they are filled.
    std::vector<std::unique_ptr<PackedLayer<Field>>> layers;
    typename ZkCommon<Field>::ExtraConstraints extra;
    {
      Built b(f_);
      build(show, &sec, b);
      if (!b.native_ok) return false;
      extra = b.links.resolve(*lay_);
      Timestamps ts = sec.ts;
      ts.now = show.now;
      ts.max_birth = show.max_birth;
      layers = fill(b, ts, /*public_only=*/false);
    }
    const auto w = pointers(layers);
    proof_ = std::make_unique<ZkMultiProof<Field>>(*lay_, kRate, kQueries);
    ZkMultiProver<Field, RS> prover(*lay_, f_, rs_.factory);
    Transcript tp((uint8_t*)"pq-credential", 13);
    prover.commit(*proof_, w, tp, rng_);
    if (!prover.prove(*proof_, w, tp, extra)) return false;
    if (!kCft) return true;

    BuiltQ bq(fq_);
    build_q(show, &sec, bq);
    const auto extra_q = bq.links.resolve(*lay_q_);
    auto q0 = fill_sponge<FieldQ>(bq.sponge, *sponge_q_, false, fq_);
    PackedLayer<FieldQ> q1(1, lwec_->ninputs, fq_);
    std::array<uint8_t, kLweMsgBytes> m;
    for (size_t i = 0; i < kLweMsgBytes; ++i) m[i] = byte_of(bq.msg, i);
    fill_lwe(q1, fq_, show.ct, &m, &sec.rnd);
    const std::vector<const PackedLayer<FieldQ>*> wq{q0.get(), &q1};
    proof_q_ =
        std::make_unique<ZkMultiProof<FieldQ>>(*lay_q_, kRate, kQueries);
    ZkMultiProver<FieldQ, RSQ> prover_q(*lay_q_, fq_, rsq_.factory);
    Transcript tq((uint8_t*)"pq-credential-lwe", 17);
    prover_q.commit(*proof_q_, wq, tq, rng_);
    return prover_q.prove(*proof_q_, wq, tq, extra_q);
  }

  // Verifies the serialized proofs of the last Prove() against SHOW.
  bool Verify(const Show& show) const {
    {
      ZkMultiProof<Field> proof(*lay_, kRate, kQueries);
      if (!roundtrip(*proof_, proof, f_)) return false;
      std::vector<std::unique_ptr<PackedLayer<Field>>> layers;
      typename ZkCommon<Field>::ExtraConstraints extra;
      {
        Built b(f_);
        build(show, nullptr, b);
        extra = b.links.resolve(*lay_);
        Timestamps ts{};
        ts.now = show.now;
        ts.max_birth = show.max_birth;
        layers = fill(b, ts, /*public_only=*/true);
      }
      ZkMultiVerifier<Field, RS> verifier(*lay_, rs_.factory, kRate, kQueries,
                                          f_);
      Transcript tv((uint8_t*)"pq-credential", 13);
      verifier.recv_commitment(proof, tv);
      if (!verifier.verify(proof, pointers(layers), tv, extra)) return false;
    }
    if (!kCft) return true;
    ZkMultiProof<FieldQ> proof(*lay_q_, kRate, kQueries);
    if (!roundtrip(*proof_q_, proof, fq_)) return false;
    BuiltQ bq(fq_);
    build_q(show, nullptr, bq);
    const auto extra = bq.links.resolve(*lay_q_);
    auto q0 = fill_sponge<FieldQ>(bq.sponge, *sponge_q_, true, fq_);
    PackedLayer<FieldQ> q1(1, Lwec::kNPub, fq_);
    fill_lwe<FieldQ, LP>(q1, fq_, show.ct, nullptr, nullptr);
    ZkMultiVerifier<FieldQ, RSQ> verifier(*lay_q_, rsq_.factory, kRate,
                                          kQueries, fq_);
    Transcript tq((uint8_t*)"pq-credential-lwe", 17);
    verifier.recv_commitment(proof, tq);
    return verifier.verify(proof, {q0.get(), &q1}, tq, extra);
  }

  size_t ProofBytes() const {
    std::vector<uint8_t> buf;
    proof_->write(buf, f_);
    if (kCft) proof_q_->write(buf, fq_);
    return buf.size();
  }

  // The soundness of the main proof and, with CFT, of the encryption proof.
  std::vector<ZkSoundness> Soundness() const {
    std::vector<ZkSoundness> r;
    r.push_back(soundness(*lay_, f_, double(Field::kBits)));
    if (kCft) {
      r.push_back(soundness(*lay_q_, fq_,
                            12 * std::log2(double(ml_dsa::Fq().m_))));
    }
    return r;
  }

  // H = SHAKE256(ID || R2 || SALT), the public binding of the two proofs.
  static std::vector<uint8_t> binding(const std::vector<uint8_t>& id,
                                      const std::array<uint8_t, 32>& r2,
                                      const std::array<uint8_t, 32>& salt) {
    std::vector<uint8_t> in(id);
    in.insert(in.end(), r2.begin(), r2.end());
    in.insert(in.end(), salt.begin(), salt.end());
    return shake256(in, kHashDigestSize);
  }

 private:
  struct Built {
    explicit Built(const Field& f) : links(f), sponge(kSponge, links) {}
    Links<Field> links;
    Sponge<Field> sponge;
    std::vector<slh_dsa::Copy> copies;  // of both plans, issuer first
    // KIND[one]: the indices into COPIES of the general (0) and the
    // one-block (1) copies, in order; LOCAL[c]: the index of copy C there.
    std::vector<uint32_t> kind[2];
    std::vector<uint32_t> local;
    bool native_ok = true;
  };

  struct BuiltQ {
    explicit BuiltQ(const FieldQ& f) : links(f), sponge(kSpongeQ, links) {}
    Links<FieldQ> links;
    Sponge<FieldQ> sponge;
    Bytes msg;  // ID || R2, references to the sponge data
  };

  // The copies and links of the main proof; SEC is null for the verifier.
  void build(const Show& show, const Secret* sec, Built& b) const {
    Secret zero;
    if (sec == nullptr) {
      zero.user_pk.assign(P::pk_bytes, 0);
      zero.issuer_sig.assign(P::sig_bytes, 0);
      zero.user_sig.assign(P::sig_bytes, 0);
      sec = &zero;
    }
    check(sec->user_pk.size() == P::pk_bytes &&
              show.issuer_pk.size() == P::pk_bytes,
          "SLH-DSA public key length");
    Sponge<Field>& sp = b.sponge;

    // ID of the user key, and the key bits for the plan.
    Bytes pk;
    const Bytes id =
        sp.shake(kShake256Rate, free_bytes(sec->user_pk.data(), P::pk_bytes),
                 kIdBytes, &pk);
    const CredentialRefs cred = hash_credential(sp, sec->cred, id, kCft);
    Bytes msg;
    if (kCft) {
      const Bytes t = const_bytes(show.t.data(), 32);
      const Bytes r2_free = free_bytes(sec->r2.data(), 32);
      Bytes in;
      msg = sp.shake(kShake256Rate, cat({&t, &r2_free}), kHashDigestSize, &in);
      const Bytes r2 = slice(in, 32, 32);
      const Bytes salt = free_bytes(sec->salt.data(), kSaltBytes);
      const Bytes h = sp.shake(kShake256Rate, cat({&id, &r2, &salt}),
                               kHashDigestSize);
      check(show.h.size() == kHashDigestSize, "binding length");
      for (size_t i = 0; i < h.size(); ++i) {
        b.links.fixed(h[i].r,
                      (show.h[i / 8] >> (i % 8)) & 1 ? f_.one() : f_.zero());
      }
    } else {
      msg = const_bytes(show.nonce.data(), 32);
    }

    // The plans: external bits are pq_cred bits, by index into EXT.
    std::vector<Bit> ext;
    auto to_val = [&](const Bytes& v) {
      slh_dsa::Val r;
      r.bits.reserve(v.size());
      for (const Bit& x : v) {
        if (x.kind == Bit::kConst) {
          r.bits.push_back(slh_dsa::Bit::konst(x.value));
        } else {
          r.bits.push_back(slh_dsa::Bit::external(
              x.value, static_cast<uint32_t>(ext.size())));
          ext.push_back(x);
        }
      }
      return r;
    };
    const std::vector<uint8_t> ctx;
    slh_dsa::Plan<P> issuer(
        slh_dsa::Val::konst(show.issuer_pk.data(), P::n),
        slh_dsa::Val::konst(show.issuer_pk.data() + P::n, P::n), ctx,
        to_val(cred.digest), sec->issuer_sig, /*sig_public=*/false,
        /*one_block=*/true);
    // With CFT, the user's signature is the public C4.
    slh_dsa::Plan<P> user(to_val(slice(pk, 0, P::n)),
                          to_val(slice(pk, P::n, P::n)), ctx, to_val(msg),
                          kCft ? show.c4 : sec->user_sig,
                          /*sig_public=*/kCft, /*one_block=*/true);
    b.native_ok = issuer.native_ok && user.native_ok;
    const size_t nissuer = issuer.copies.size();
    const size_t ncopies = nissuer + user.copies.size();
    b.local.resize(ncopies);
    for (size_t c = 0; c < ncopies; ++c) {
      const bool one = c < nissuer ? issuer.copies[c].one
                                   : user.copies[c - nissuer].one;
      b.local[c] = static_cast<uint32_t>(b.kind[one].size());
      b.kind[one].push_back(static_cast<uint32_t>(c));
    }
    plan_links(issuer, 0, b, ext, b.links);
    plan_links(user, nissuer, b, ext, b.links);
    // The copies move into B; the plans' links are no longer needed.
    b.copies = std::move(issuer.copies);
    b.copies.insert(b.copies.end(), std::make_move_iterator(user.copies.begin()),
                    std::make_move_iterator(user.copies.end()));

    for (size_t k = 0; k < 3; ++k) {
      for (size_t t = 0; t < kTsBits; ++t) {
        b.links.bit(Ref{kAge, 0, uint32_t(k * kTsBits + t)}, cred.ts[k][t]);
      }
    }
  }

  // The links of PLAN, whose copies start at FIRST in B.copies.
  void plan_links(const slh_dsa::Plan<P>& plan, size_t first, const Built& b,
                  const std::vector<Bit>& ext, Links<Field>& l) const {
    auto ref = [&](const slh_dsa::Wire& w) {
      const size_t g = first + w.copy;
      const bool one = plan.copies[w.copy].one;
      const size_t k = b.local[g];
      return Ref{static_cast<uint32_t>(first_part(one) + k / kStepChunk),
                 static_cast<uint32_t>(k % kStepChunk), w.off};
    };
    for (const auto& [x, y] : plan.eq) l.eq(ref(x), ref(y));
    for (const auto& [x, v] : plan.fixed) {
      l.fixed(ref(x), v ? f_.one() : f_.zero());
    }
    for (const auto& [x, y, z] : plan.sum) {
      l.term(ref(x), false);
      l.term(ref(y), true);
      l.term(ref(z), true);
      l.end(f_.zero());
    }
    for (const auto& [xy, v] : plan.sum_fixed) {
      l.term(ref(xy.first), false);
      l.term(ref(xy.second), true);
      l.end(v ? f_.one() : f_.zero());
    }
    for (const auto& [x, e] : plan.ext_eq) l.bit(ref(x), ext.at(e));
    for (const auto& [xy, e] : plan.ext_sum) {
      // x = y xor e, with e a reference (external bits are not constants).
      const Bit& src = ext.at(e);
      check(src.kind == Bit::kRef, "external bit is a reference");
      l.term(ref(xy.first), false);
      l.term(ref(xy.second), true);
      l.term(src.r, true);
      l.end(f_.zero());
    }
  }

  // The encryption proof: H from private ID, R2 and SALT, and the LWE
  // message ID || R2 from the same bytes.
  void build_q(const Show& show, const Secret* sec, BuiltQ& b) const {
    std::vector<uint8_t> in(kIdBytes + 32 + kSaltBytes, 0);
    if (sec != nullptr) {
      const auto id = shake256(sec->user_pk, kIdBytes);
      std::copy(id.begin(), id.end(), in.begin());
      std::copy(sec->r2.begin(), sec->r2.end(), in.begin() + kIdBytes);
      std::copy(sec->salt.begin(), sec->salt.end(),
                in.begin() + kIdBytes + 32);
    }
    Bytes refs;
    const Bytes h = b.sponge.shake(kShake256Rate, free_bytes(in.data(), in.size()),
                                   kHashDigestSize, &refs);
    for (size_t i = 0; i < h.size(); ++i) {
      b.links.fixed(h[i].r,
                    (show.h[i / 8] >> (i % 8)) & 1 ? fq_.one() : fq_.zero());
    }
    b.msg = slice(refs, 0, kLweMsgBytes);
    for (size_t i = 0; i < b.msg.size(); ++i) {
      b.links.bit(Ref{kLweQ, 0, uint32_t(Lwec::kMsg + i)}, b.msg[i]);
    }
  }

  // The step parts of the general (ONE false) or one-block copies.
  size_t parts_of(bool one) const {
    return (nstep_[one] + kStepChunk - 1) / kStepChunk;
  }
  size_t step_parts() const { return parts_of(false) + parts_of(true); }
  // The first part of the general or one-block copies.
  size_t first_part(bool one) const {
    return kStep0 + (one ? parts_of(false) : 0);
  }

  // The circuit of step part K (counted from kStep0): kStepChunk copies of
  // one kind, or the rest.
  const Circuit<Field>& step(size_t k) const {
    const bool one = k >= parts_of(false);
    const size_t j = one ? k - parts_of(false) : k;
    return (j + 1) * kStepChunk <= nstep_[one] ? *step_full_[one]
                                               : *step_last_[one];
  }

  // The inputs of the parts of the main proof (public only for the
  // verifier), in part order.
  std::vector<std::unique_ptr<PackedLayer<Field>>> fill(const Built& b,
                                                        const Timestamps& ts,
                                                        bool public_only) const {
    check(b.kind[0].size() == nstep_[0] && b.kind[1].size() == nstep_[1],
          "step copies");
    std::vector<std::unique_ptr<PackedLayer<Field>>> r;
    r.push_back(fill_sponge<Field>(b.sponge, *sponge_, public_only, f_));
    r.push_back(std::make_unique<PackedLayer<Field>>(
        1, public_only ? AgeCircuit<LC>::kNPub : age_->ninputs, f_));
    fill_age(*r.back(), ts, public_only);
    for (size_t k = 0; k < step_parts(); ++k) {
      const Circuit<Field>& c = step(k);
      const bool one = k >= parts_of(false);
      const size_t first = (one ? k - parts_of(false) : k) * kStepChunk;
      r.push_back(std::make_unique<PackedLayer<Field>>(
          c.nc, public_only ? c.npub_in : c.ninputs, f_));
      for (size_t i = 0; i < c.nc; ++i) {
        const slh_dsa::Copy& cp = b.copies[b.kind[one][first + i]];
        if (one) {
          Zk::fill_public1(cp, *r.back(), i, f_);
          if (!public_only) Zk::fill_private1(cp, *r.back(), i, f_);
        } else {
          Zk::fill_public(cp, *r.back(), i, f_);
          if (!public_only) Zk::fill_private(cp, *r.back(), i, f_);
        }
      }
    }
    return r;
  }

  template <class F>
  static std::vector<const PackedLayer<F>*> pointers(
      const std::vector<std::unique_ptr<PackedLayer<F>>>& v) {
    std::vector<const PackedLayer<F>*> r;
    r.reserve(v.size());
    for (const auto& x : v) r.push_back(x.get());
    return r;
  }

  template <class F, class L>
  static std::unique_ptr<Circuit<F>> make_sponge(const F& f, size_t nc) {
    return compile<F, L>(f, "sponge", nc, [](const L& lc, QuadCircuit<F>& Q) {
      typename SpongeStep<L>::Public u;
      typename SpongeStep<L>::Private w;
      Sponge<F>::inputs(lc, Q, u, w);
      Q.begin_full_field();
      SpongeStep<L>(lc).assert_step(u, w);
    });
  }

  // The circuit NAME of BODY for NC copies, stored once with
  // PQ_CIRCUIT_CACHE (circuit_cache.h).
  template <class F, class L, class Body>
  static std::unique_ptr<Circuit<F>> compile(const F& f,
                                             const std::string& name,
                                             size_t nc, const Body& body) {
    return cached_circuit(f, "slh_cred_" + name + "_nc" + std::to_string(nc),
                          [&] {
                            QuadCircuit<F> Q(f);
                            const CompilerBackend<F> cbk(&Q);
                            const L lc(&cbk, f);
                            body(lc, Q);
                            return Q.mkcircuit(nc);
                          });
  }

  template <class F>
  static std::unique_ptr<PackedLayer<F>> fill_sponge(const Sponge<F>& sp,
                                                     const Circuit<F>& c,
                                                     bool public_only,
                                                     const F& f) {
    const size_t nc = sp.copies().size();
    check(nc == c.nc, "sponge copies");
    auto w = std::make_unique<PackedLayer<F>>(
        nc, public_only ? SpongeLayout::npub : c.ninputs, f);
    for (size_t k = 0; k < nc; ++k) sp.fill(*w, k, public_only);
    return w;
  }

  template <class F>
  static bool roundtrip(const ZkMultiProof<F>& from, ZkMultiProof<F>& to,
                        const F& f) {
    std::vector<uint8_t> bytes;
    from.write(bytes, f);
    ReadBuffer rb(bytes);
    return to.read(rb, f);
  }

  template <class F>
  static ZkSoundness soundness(const ZkMultiLayout<F>& lay, const F& f,
                               double log2_field) {
    std::vector<const Circuit<F>*> cs;
    for (size_t p = 0; p < lay.parts(); ++p) cs.push_back(&lay.circuit(p));
    const ZkMultiProof<F> proof(lay, kRate, kQueries);
    return zk_soundness(cs, proof.param, log2_field);
  }

  const Field f_;
  const FieldQ fq_{ml_dsa::Fq(), 7};
  const LwePublic<LP> lwe_;
  const slh_dsa::ZkRs<Field> rs_;
  const MlDsaRs<FieldQ> rsq_{ml_dsa::Fq()};
  size_t nstep_[2] = {0, 0};  // general and one-block step copies
  std::unique_ptr<Circuit<Field>> step_full_[2], step_last_[2];
  std::unique_ptr<Circuit<Field>> sponge_, age_;
  std::unique_ptr<Circuit<FieldQ>> sponge_q_, lwec_;
  std::unique_ptr<ZkMultiLayout<Field>> lay_;
  std::unique_ptr<ZkMultiLayout<FieldQ>> lay_q_;
  SecureRandomEngine rng_;
  std::unique_ptr<ZkMultiProof<Field>> proof_;
  std::unique_ptr<ZkMultiProof<FieldQ>> proof_q_;
};

}  // namespace pq_cred
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_SLH_DSA_CRED_H_
