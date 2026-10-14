// ZK proof of SLH-DSA verification over copies of the hash-step circuit
// (not upstream).
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!  Experimental research code.
//
// Statement: a valid SLH-DSA signature on a private message of public
// length, under a public key and a public context. The proof field and the
// Ligero queries follow the NIST category of the parameter set (ZkCategory3,
// ZkCategory5 below).

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_ZK_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_ZK_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include "arrays/dense.h"
#include "arrays/packed_layer.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/slh_dsa/slh_dsa.h"
#include "circuits/tests/pq/slh_dsa/slh_dsa_circuit.h"
#include "algebra/reed_solomon_componentwise.h"
#include "gf2k/gf2_128.h"
#include "gf2k/gf2_128_ext.h"
#include "util/crypto.h"
#include "util/readbuffer.h"
#include "gf2k/lch14_reed_solomon.h"
#include "ligero/ligero_param.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/panic.h"
#include "zk/zk_common.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace slh_dsa {

// Proof field, Ligero queries (rate 4) and SHAKE256 digest size of a NIST
// category. slh_dsa_zk_test checks the soundness bits (zk/zk_soundness.h).
//   ZkCategory3: GF(2^256), 281 queries, 48-byte digests: at least 192 bits.
//   ZkCategory5: GF(2^384), 374 queries, 64-byte digests: at least 256 bits.
// The digest size is fixed per program (PROOFS_SHAKE256_DIGEST_BYTES), so
// the category 3 and 5 proofs are separate programs (slh_dsa_zk_test and
// slh_dsa_zk_5_test).
struct ZkCategory3 {
  using Field = GF2_128Ext<2>;
  static constexpr size_t kQueries = 281;
  static constexpr size_t kDigestBytes = 48;
};
struct ZkCategory5 {
  using Field = GF2_128Ext<3>;
  static constexpr size_t kQueries = 374;
  static constexpr size_t kDigestBytes = 64;
};
template <class P>
using DefaultZk = std::conditional_t<P::n == 24, ZkCategory3, ZkCategory5>;

// The Reed-Solomon code of a proof field: LCH14 over GF(2^128), coordinate
// by coordinate.
template <class Field>
struct ZkRs {
  using Base = LCH14ReedSolomonFactory<GF2_128<>>;
  using Factory = ComponentwiseReedSolomonFactory<Field, Base>;
  explicit ZkRs(const Field& f) : base(f.base_field()), factory(base) {}
  const Base base;
  const Factory factory;
};

template <class P, class Z = DefaultZk<P>>
class SlhDsaZk {
  static_assert(kHashDigestSize == Z::kDigestBytes,
                "build with PROOFS_SHAKE256_DIGEST_BYTES = Z::kDigestBytes");

 public:
  using Field = typename Z::Field;

 private:
  using Elt = typename Field::Elt;
  using LogicCircuit = Logic<Field, CompilerBackend<Field>>;
  using Step = StepCircuit<LogicCircuit, P::n>;
  using RSFactory = typename ZkRs<Field>::Factory;
  using Common = ZkCommon<Field>;
  using Llc = LigeroLinearConstraint<Field>;
  using L = Layout<P::n>;

 public:
  static constexpr size_t kLigeroRate = 4;
  static constexpr size_t kLigeroQueries = Z::kQueries;

  // Longest message; each 136 bytes add one copy. Not a FIPS 205 limit: it
  // bounds the memory and time of the statement.
  static constexpr size_t kMaxMessageBytes = size_t(1) << 16;

  // The verifier's view: public key, context and message length. Builds the
  // copies and links from a zero signature and compiles the circuit. Returns
  // nullptr if PK or CTX has a wrong length or MSG_LEN > kMaxMessageBytes.
  static std::unique_ptr<SlhDsaZk> Make(std::vector<uint8_t> pk,
                                        std::vector<uint8_t> ctx,
                                        size_t msg_len) {
    if (!Plan<P>::valid_statement(pk, ctx) || msg_len > kMaxMessageBytes) {
      return nullptr;
    }
    return std::unique_ptr<SlhDsaZk>(
        new SlhDsaZk(std::move(pk), std::move(ctx), msg_len));
  }

 private:
  SlhDsaZk(std::vector<uint8_t> pk, std::vector<uint8_t> ctx, size_t msg_len)
      : pk_(std::move(pk)),
        ctx_(std::move(ctx)),
        msg_len_(msg_len),
        plan_(pk_, ctx_, std::vector<uint8_t>(msg_len_, 0),
              std::vector<uint8_t>(P::sig_bytes, 0)),
        circuit_(make_circuit(plan_.copies.size())),
        rs_(f_) {
    check(circuit_->npub_in == L::npub, "public input layout");
    check(circuit_->ninputs == L::npub + L::npriv, "private input layout");
    extra_ = constraints(plan_, *circuit_);
  }

 public:
  size_t copies() const { return plan_.copies.size(); }
  size_t links() const { return extra_.b.size(); }
  const Circuit<Field>& circuit() const { return *circuit_; }

  // Returns false if MSG or SIG has a wrong length or the signature does not
  // verify natively.
  bool Prove(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig) {
    if (msg.size() != msg_len_) return false;
    const Plan<P> plan(pk_, ctx_, msg, sig);
    if (!plan.native_ok) return false;
    check(same_structure(plan, plan_), "plan depends on the witness");

    const size_t nc = plan.copies.size();
    // Every input is a bit: the inputs are filled packed, one bit per input
    // and copy (12.6 MB for 256f instead of 4.8 GB).
    PackedLayer<Field> w(nc, circuit_->ninputs, f_);
    for (size_t c = 0; c < nc; ++c) {
      fill_public(plan.copies[c], w, c, f_);
      fill_private(plan.copies[c], w, c, f_);
    }
    zkpr_ = std::make_unique<ZkProof<Field>>(*circuit_, kLigeroRate,
                                             kLigeroQueries);
    ZkProver<Field, RSFactory> prover(*circuit_, f_, rs_.factory);
    Transcript tp((uint8_t*)"slh-dsa", 7);
    prover.commit(*zkpr_, w, tp, rng_);
    return prover.prove(*zkpr_, w, tp, &extra_);
  }

  // With TAMPER, the first PUB bit of copy 0 is flipped, and verification
  // must fail.
  // The proof is serialized and parsed (ZkProof::read) first, as a verifier
  // receives it.
  bool Verify(bool tamper = false) const {
    std::vector<uint8_t> bytes;
    zkpr_->write(bytes, f_);
    ZkProof<Field> proof(*circuit_, kLigeroRate, kLigeroQueries);
    ReadBuffer rb(bytes);
    if (!proof.read(rb, f_)) return false;

    // The public inputs, packed (all bits).
    const size_t nc = plan_.copies.size();
    PackedLayer<Field> pub(nc, L::npub, f_);
    Copy first = plan_.copies[0];
    if (tamper) first.pub[0] ^= 1;
    fill_public(first, pub, 0, f_);
    for (size_t c = 1; c < nc; ++c) fill_public(plan_.copies[c], pub, c, f_);
    ZkVerifier<Field, RSFactory> verifier(*circuit_, rs_.factory, kLigeroRate,
                                          kLigeroQueries, f_);
    Transcript tv((uint8_t*)"slh-dsa", 7);
    verifier.recv_commitment(proof, tv);
    return verifier.verify(proof, pub, tv, &extra_);
  }

  size_t ProofBytes() const {
    std::vector<uint8_t> buf;
    zkpr_->write(buf, f_);
    return buf.size();
  }

  // Sets input I of copy C, in the layout of the prover's inputs (Dense or
  // PackedLayer).
  static void set(Dense<Field>& w, size_t i, size_t c, bool bit,
                  const Field& f) {
    w.v_[w.n0_ * i + c] = bit ? f.one() : f.zero();
  }
  static void set(PackedLayer<Field>& w, size_t i, size_t c, bool bit,
                  const Field&) {
    w.set_bit(i, c, bit);
  }
  template <class In>
  static void set_bits(In& w, size_t& i, size_t c, uint64_t x, size_t nbits,
                       const Field& f) {
    for (size_t b = 0; b < nbits; ++b) set(w, i++, c, (x >> b) & 1, f);
  }

  // The public inputs of copy CP as copy C of W, in the prover layout.
  template <class In>
  static void fill_public(const Copy& cp, In& w, size_t c,
                          const Field& f) {
    size_t i = 0;
    set(w, i++, c, true, f);  // the constant one
    for (size_t k = 0; k < kRate; ++k) set_bits(w, i, c, cp.pub[k], 8, f);
    for (size_t k = 0; k < kRate; ++k) set_bits(w, i, c, cp.mask[k], 8, f);
    set(w, i++, c, cp.cont, f);
    set(w, i++, c, cp.swap_en, f);
    set(w, i++, c, cp.is_wots, f);
    set_bits(w, i, c, cp.j, 4, f);
    set(w, i++, c, cp.is_acc, f);
    check(i == L::npub, "public input count");
  }

  // The private inputs of copy CP as copy C of W, in the prover layout.
  template <class In>
  static void fill_private(const Copy& cp, In& w, size_t c,
                           const Field& f) {
    size_t i = L::npub;
    for (size_t j = 0; j < kCapLanes; ++j) set_bits(w, i, c, cp.cap[j], 64, f);
    for (size_t k = 0; k < kRate; ++k) set_bits(w, i, c, cp.block[k], 8, f);
    set(w, i++, c, cp.swap, f);
    set_bits(w, i, c, cp.digit, 4, f);
    set_bits(w, i, c, cp.acc_in, kAccBits, f);
    set_bits(w, i, c, cp.acc_out, kAccBits, f);
    for (size_t k = 0; k < P::n; ++k) set_bits(w, i, c, cp.r[k], 8, f);
    for (size_t round = 0; round < 24; ++round) {
      if (!sha3_slice_at(round)) continue;
      for (size_t x = 0; x < 5; ++x) {
        for (size_t y = 0; y < 5; ++y) {
          set_bits(w, i, c, cp.bw.a_intermediate[round][x][y], 64, f);
        }
      }
    }
    check(i == L::npub + L::npriv, "private input count");
  }

  static std::unique_ptr<Circuit<Field>> make_circuit(size_t nc) {
    const Field f;
    QuadCircuit<Field> Q(f);
    const CompilerBackend<Field> cbk(&Q);
    const LogicCircuit lc(&cbk, f);
    const Step step(lc);
    typename Step::Public u;
    u.input(lc);
    Q.private_input();
    typename Step::Private w;
    w.input(lc);
    // Every input is a bit: the witness is in the subfield GF(2^16), so its
    // Ligero rows take subfield randomness and their opened elements are
    // sent in 2 bytes.
    Q.begin_full_field();
    step.assert_step(u, w);
    return Q.mkcircuit(nc);
  }

 private:
  // The links of PLAN as linear constraints on the committed witness.
  static typename Common::ExtraConstraints constraints(
      const Plan<P>& plan, const Circuit<Field>& circuit) {
    const Field f;
    typename Common::ExtraConstraints e;
    auto index = [&](const Wire& w) {
      return Common::witness_index(circuit, L::npub + w.off, w.copy);
    };
    e.a.reserve(2 * plan.eq.size() + plan.fixed.size() + 3 * plan.sum.size() +
                2 * plan.sum_fixed.size());
    e.b.reserve(plan.eq.size() + plan.fixed.size() + plan.sum.size() +
                plan.sum_fixed.size());
    size_t row = 0;
    for (const auto& [x, y] : plan.eq) {
      e.a.push_back(Llc{row, index(x), f.one()});
      e.a.push_back(Llc{row, index(y), f.mone()});
      e.b.push_back(f.zero());
      ++row;
    }
    for (const auto& [x, value] : plan.fixed) {
      e.a.push_back(Llc{row, index(x), f.one()});
      e.b.push_back(value ? f.one() : f.zero());
      ++row;
    }
    for (const auto& [x, y, z] : plan.sum) {
      e.a.push_back(Llc{row, index(x), f.one()});
      e.a.push_back(Llc{row, index(y), f.mone()});
      e.a.push_back(Llc{row, index(z), f.mone()});
      e.b.push_back(f.zero());
      ++row;
    }
    for (const auto& [xy, value] : plan.sum_fixed) {
      e.a.push_back(Llc{row, index(xy.first), f.one()});
      e.a.push_back(Llc{row, index(xy.second), f.mone()});
      e.b.push_back(value ? f.one() : f.zero());
      ++row;
    }
    return e;
  }

  static bool same_structure(const Plan<P>& x, const Plan<P>& y) {
    if (x.copies.size() != y.copies.size() || x.eq != y.eq ||
        x.fixed != y.fixed || x.sum != y.sum || x.sum_fixed != y.sum_fixed) {
      return false;
    }
    for (size_t c = 0; c < x.copies.size(); ++c) {
      const Copy &p = x.copies[c], &q = y.copies[c];
      if (std::memcmp(p.pub, q.pub, kRate) != 0 ||
          std::memcmp(p.mask, q.mask, kRate) != 0 || p.cont != q.cont ||
          p.swap_en != q.swap_en || p.is_wots != q.is_wots ||
          p.is_acc != q.is_acc || p.j != q.j) {
        return false;
      }
    }
    return true;
  }

  const Field f_;
  const std::vector<uint8_t> pk_, ctx_;
  const size_t msg_len_;
  const Plan<P> plan_;  // the verifier's
  const std::unique_ptr<Circuit<Field>> circuit_;
  const ZkRs<Field> rs_;
  typename Common::ExtraConstraints extra_;
  SecureRandomEngine rng_;
  std::unique_ptr<ZkProof<Field>> zkpr_;
};

}  // namespace slh_dsa
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_ZK_H_
