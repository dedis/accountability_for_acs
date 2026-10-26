// Zero-knowledge proof of several circuits over one Ligero commitment (not
// upstream).
//
// Each part is a circuit with copies and its own inputs (zk/zk_common.h).
// The committed vector holds the private inputs of every part, in part
// order, then the sumcheck pads of every part. Extra linear constraints
// (ZkCommon::ExtraConstraints, on indices of the whole vector) link the
// parts. After the commitment, the sumcheck of each part runs in part
// order on one transcript; the Ligero proof then checks the constraints of
// all parts and the extra constraints at once.

#ifndef PRIVACY_PROOFS_ZK_LIB_ZK_ZK_MULTI_H_
#define PRIVACY_PROOFS_ZK_LIB_ZK_ZK_MULTI_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "arrays/packed_layer.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_prover.h"
#include "ligero/ligero_verifier.h"
#include "random/random.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/prover_layers.h"
#include "sumcheck/transcript_sumcheck.h"
#include "util/log.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_common.h"
#include "zk/zk_proof.h"

namespace proofs {

// The parts of a proof and the layout of the committed vector.
template <class Field>
class ZkMultiLayout {
  using Common = ZkCommon<Field>;

 public:
  // STRIDE[p]: the layer checkpoint stride of part P in the sumcheck prover
  // (ProverLayers::prove_low_memory; 0: about sqrt(layers), 1: every layer
  // kept). Empty: 0 for every part. Checkpointing trades one more
  // evaluation for memory; it pays for layers of full field elements, not
  // for layers of bits, which are packed.
  explicit ZkMultiLayout(std::vector<const Circuit<Field>*> c,
                         std::vector<size_t> stride = {})
      : c_(std::move(c)), stride_(std::move(stride)) {
    check(!c_.empty(), "no circuit");
    if (stride_.empty()) stride_.assign(c_.size(), 0);
    check(stride_.size() == c_.size(), "one stride per part");
    for (const Circuit<Field>* ci : c_) {
      // The witnesses of all parts are under one subfield boundary.
      check(ci->subfield_boundary == ci->ninputs,
            "every input of a part must be in the subfield");
      first_.push_back(nw_);
      nw_ += Common::num_witness(*ci);
      nq_ += ci->nl;
      nterms_ += Common::num_terms(*ci);
    }
    size_t pad = nw_;
    for (const Circuit<Field>* ci : c_) {
      pad_.push_back(pad);
      pad += Common::pad_size(*ci);
    }
    size_ = pad;
  }

  size_t parts() const { return c_.size(); }
  size_t stride(size_t p) const { return stride_[p]; }
  const Circuit<Field>& circuit(size_t p) const { return *c_[p]; }
  // Index of the first private input of part P in the committed vector.
  size_t first(size_t p) const { return first_[p]; }
  // Index of the first pad element of part P.
  size_t pad(size_t p) const { return pad_[p]; }
  // Committed private inputs of all parts.
  size_t num_witness() const { return nw_; }
  // Length of the committed vector.
  size_t size() const { return size_; }
  // Quadratic constraints: one per layer of every part.
  size_t nq() const { return nq_; }

  // The Ligero parameters of the committed vector. The witness rows are
  // hashed by subfield bytes (LigeroParam::nsub): every witness lies in the
  // subfield (checked by ZkMultiProver::commit), the pads do not.
  LigeroParam<Field> ligero_param(size_t rate, size_t req) const {
    LigeroParam<Field> p(size_, nq_, rate, req);
    p.hash_subfield_rows(nw_);
    return p;
  }
  // Linear-constraint terms of the sumchecks of all parts.
  size_t nterms() const { return nterms_; }

  // Index of private input I of copy C of part P.
  size_t index(size_t p, size_t i, size_t c) const {
    return first_[p] + Common::witness_index(*c_[p], i, c);
  }

  // The quadratic constraints of all parts, on their pads.
  std::vector<LigeroQuadraticConstraint> lqc() const {
    std::vector<LigeroQuadraticConstraint> r;
    r.reserve(nq_);
    for (size_t p = 0; p < c_.size(); ++p) {
      std::vector<LigeroQuadraticConstraint> one(c_[p]->nl);
      Common::setup_lqc(*c_[p], one, pad_[p]);
      r.insert(r.end(), one.begin(), one.end());
    }
    return r;
  }

  // True if every row of E is below b.size() and every column is a
  // committed private input (not a pad element).
  bool extra_valid(const typename Common::ExtraConstraints& e) const {
    for (const auto& t : e.a) {
      if (t.c >= e.b.size() || t.w >= nw_) return false;
    }
    return true;
  }

 private:
  std::vector<const Circuit<Field>*> c_;
  std::vector<size_t> stride_;
  std::vector<size_t> first_, pad_;
  size_t nw_ = 0, nq_ = 0, nterms_ = 0, size_ = 0;
};

// The proof: the commitment, one sumcheck proof per part, the Ligero proof.
template <class Field>
struct ZkMultiProof {
  using Io = ZkProof<Field>;

  const ZkMultiLayout<Field>& lay;
  std::vector<Proof<Field>> proof;
  LigeroParam<Field> param;
  LigeroCommitment<Field> com;
  LigeroProof<Field> com_proof;

  ZkMultiProof(const ZkMultiLayout<Field>& l, size_t rate, size_t req)
      : lay(l), param(l.ligero_param(rate, req)), com_proof(&param) {
    proof.reserve(l.parts());
    for (size_t p = 0; p < l.parts(); ++p) proof.emplace_back(l.circuit(p).nl);
  }

  void write(std::vector<uint8_t>& buf, const Field& F) const {
    Io::write_com(com, buf, F);
    for (size_t p = 0; p < lay.parts(); ++p) {
      Io::write_sc(lay.circuit(p), proof[p], buf, F);
    }
    Io::write_com_proof(com_proof, buf, F);
  }

  // False on error, underflow, or bytes after the proof.
  bool read(ReadBuffer& buf, const Field& F) {
    if (!Io::read_com(com, buf, F)) return false;
    for (size_t p = 0; p < lay.parts(); ++p) {
      if (!Io::read_sc(lay.circuit(p), proof[p], buf, F)) return false;
    }
    if (!Io::read_com_proof(com_proof, buf, F)) return false;
    return buf.remaining() == 0;
  }
};

template <class Field, class ReedSolomonFactory>
class ZkMultiProver : public ProverLayers<Field> {
  using super = ProverLayers<Field>;
  using typename super::bindings;
  using Elt = typename Field::Elt;
  using Common = ZkCommon<Field>;
  using Inputs = std::vector<const PackedLayer<Field>*>;

 public:
  ZkMultiProver(const ZkMultiLayout<Field>& lay, const Field& F,
                const ReedSolomonFactory& rsf)
      : super(F), lay_(lay), f_(F), rsf_(rsf), lqc_(lay.lqc()) {}

  // Commits to the private inputs of every part (W[p]: all inputs of part
  // P, read in place) and to the pads. W must stay alive until prove().
  void commit(ZkMultiProof<Field>& zkp, const Inputs& W, Transcript& tp,
              RandomEngine& rng) {
    check_inputs(W);
    pad_.clear();
    pad_.reserve(lay_.parts());
    pads_.clear();
    pads_.reserve(lay_.size() - lay_.num_witness());
    for (size_t p = 0; p < lay_.parts(); ++p) {
      pad_.emplace_back(lay_.circuit(p).nl);
      fill_pad(lay_.circuit(p), pad_.back(), rng);
    }
    const Committed committed{lay_, W, pads_};
    lp_ = std::make_unique<LigeroProver<Field, ReedSolomonFactory>>(
        zkp.param, /*low_memory=*/true);
    lp_->commit(zkp.com, tp, committed, lay_.num_witness(), lqc_.data(), rsf_,
                rng, f_);
    log(INFO, "ZK multi commitment done");
  }

  // Runs the sumcheck of every part and the Ligero proof. EXTRA: the
  // linear constraints between parts.
  bool prove(ZkMultiProof<Field>& zkp, const Inputs& W, Transcript& tsp,
             const typename Common::ExtraConstraints& extra) {
    // One prove per commit: a second one would reuse the pads.
    check(lp_ != nullptr, "must run commit before prove");
    const auto lp = std::move(lp_);
    check_inputs(W);
    if (!lay_.extra_valid(extra)) {
      log(ERROR, "extra constraint index out of range");
      return false;
    }

    std::vector<LigeroLinearConstraint<Field>> a;
    std::vector<Elt> b;
    std::vector<LigeroProductRow<Field>> rows(lay_.parts());
    a.reserve(lay_.nterms());
    size_t ci = 0;
    for (size_t p = 0; p < lay_.parts(); ++p) {
      const Circuit<Field>& c = lay_.circuit(p);
      Common::initialize_sumcheck_fiat_shamir(tsp, c, *W[p], f_);
      Transcript tst = tsp.clone();
      bindings bnd;
      ProofAux<Field> aux(c.nl);
      TranscriptSumcheck<Field> tsts(tst, f_);
      if (!super::prove_low_memory(&zkp.proof[p], &pad_[p], &c, *W[p], &aux,
                                   bnd, tsts, f_, lay_.stride(p))) {
        log(ERROR, "part %zu: evaluation failed or an output is nonzero", p);
        return false;
      }
      const size_t a0 = a.size();
      const size_t n = Common::verifier_constraints(
          c, *W[p], zkp.proof[p], &aux, a, b, rows[p], tsp, lay_.pad(p), f_,
          lay_.first(p));
      for (size_t k = a0; k < a.size(); ++k) a[k].c += ci;
      rows[p].c += ci;
      ci += n;
    }
    // The extra terms are passed as they are, with their rows after the
    // sumcheck rows.
    const LigeroTermSpan<Field> span{a.data(), a.size(), 0};
    const LigeroUnitSpan<Field> units{extra.a.data(), extra.a.size(), ci,
                                      nullptr};
    ci += extra.b.size();

    lp->prove(zkp.com_proof, tsp, ci, &span, 1, units,
              Common::extra_hash(extra, f_), lqc_.data(), rsf_, f_,
              rows.data(), rows.size());
    return true;
  }

 private:
  // The committed vector: the private inputs of each part, read from its
  // packed inputs in the layout of Dense, then the pads.
  struct Committed {
    const ZkMultiLayout<Field>& lay;
    const Inputs& w;
    const std::vector<Elt>& pad;
    Elt operator[](size_t j) const {
      if (j >= lay.num_witness()) return pad[j - lay.num_witness()];
      size_t p = lay.parts() - 1;
      while (lay.first(p) > j) --p;
      const Circuit<Field>& c = lay.circuit(p);
      return w[p]->at(c.npub_in * c.nc + (j - lay.first(p)));
    }
  };

  void check_inputs(const Inputs& W) const {
    check(W.size() == lay_.parts(), "one input layer per part");
    for (size_t p = 0; p < lay_.parts(); ++p) {
      const Circuit<Field>& c = lay_.circuit(p);
      check(W[p]->n0() == c.nc && W[p]->n1() == c.ninputs,
            "inputs do not match the circuit");
    }
  }

  // ZkProver::fill_pad for circuit C: random pads into PAD, and the
  // committed elements appended to pads_.
  void fill_pad(const Circuit<Field>& c, Proof<Field>& pad, RandomEngine& rng) {
    for (size_t i = 0; i < c.nl; ++i) {
      for (size_t j = 0; j < c.logc; ++j) {
        for (size_t k = 0; k < 4; ++k) {
          const Elt r = k != 1 ? rng.elt(f_) : f_.zero();  // P(1) implied
          pad.l[i].cp[j].t_[k] = r;
          if (k != 1) pads_.push_back(r);
        }
      }
      for (size_t j = 0; j < c.l[i].logw; ++j) {
        for (size_t h = 0; h < 2; ++h) {
          for (size_t k = 0; k < 3; ++k) {
            const Elt r = k != 1 ? rng.elt(f_) : f_.zero();
            pad.l[i].hp[h][j].t_[k] = r;
            if (k != 1) pads_.push_back(r);
          }
        }
      }
      for (size_t k = 0; k < 2; ++k) {
        pad.l[i].wc[k] = rng.elt(f_);
        pads_.push_back(pad.l[i].wc[k]);
      }
      // The product of the claim pads, for the quadratic constraint.
      pads_.push_back(f_.mulf(pad.l[i].wc[0], pad.l[i].wc[1]));
    }
  }

  const ZkMultiLayout<Field>& lay_;
  const Field& f_;
  const ReedSolomonFactory& rsf_;
  const std::vector<LigeroQuadraticConstraint> lqc_;
  std::vector<Proof<Field>> pad_;
  std::vector<Elt> pads_;
  std::unique_ptr<LigeroProver<Field, ReedSolomonFactory>> lp_;
};

template <class Field, class RSFactory>
class ZkMultiVerifier {
  using Elt = typename Field::Elt;
  using Common = ZkCommon<Field>;
  using Inputs = std::vector<const PackedLayer<Field>*>;

 public:
  ZkMultiVerifier(const ZkMultiLayout<Field>& lay, const RSFactory& rsf,
                  size_t rate, size_t nreq, const Field& F)
      : lay_(lay),
        param_(lay.ligero_param(rate, nreq)),
        lqc_(lay.lqc()),
        rsf_(rsf),
        f_(F) {}

  void recv_commitment(const ZkMultiProof<Field>& zk, Transcript& t) const {
    LigeroVerifier<Field, RSFactory>::receive_commitment(zk.com, t);
  }

  // PUB[p]: exactly the public inputs of every copy of part P, packed.
  bool verify(const ZkMultiProof<Field>& zk, const Inputs& pub, Transcript& tv,
              const typename Common::ExtraConstraints& extra) const {
    if (pub.size() != lay_.parts()) return false;
    for (size_t p = 0; p < lay_.parts(); ++p) {
      const Circuit<Field>& c = lay_.circuit(p);
      if (pub[p]->n0() != c.nc || pub[p]->n1() != c.npub_in) {
        log(INFO, "verifier: public inputs do not match part %zu", p);
        return false;
      }
    }
    if (!lay_.extra_valid(extra)) {
      log(INFO, "verifier: extra constraint index out of range");
      return false;
    }
    const LigeroHash hash_of_A = Common::extra_hash(extra, f_);
    size_t nrows = extra.b.size();
    for (size_t p = 0; p < lay_.parts(); ++p) nrows += lay_.circuit(p).nl + 1;

    // Check the Merkle openings first, on a copy of the transcript.
    {
      Transcript probe = tv.clone();
      for (size_t p = 0; p < lay_.parts(); ++p) {
        const Circuit<Field>& c = lay_.circuit(p);
        Common::initialize_sumcheck_fiat_shamir(probe, c, *pub[p], f_);
        Common::replay_sumcheck(c, zk.proof[p], probe, f_);
      }
      if (!LigeroVerifier<Field, RSFactory>::check_openings(
              param_, zk.com, zk.com_proof, probe, nrows, hash_of_A, f_)) {
        log(INFO, "verifier: merkle_check failed");
        return false;
      }
    }

    std::vector<LigeroLinearConstraint<Field>> A;
    std::vector<Elt> b;
    std::vector<LigeroProductRow<Field>> rows(lay_.parts());
    A.reserve(lay_.nterms());
    b.reserve(nrows - extra.b.size());
    size_t cn = 0;
    for (size_t p = 0; p < lay_.parts(); ++p) {
      const Circuit<Field>& c = lay_.circuit(p);
      Common::initialize_sumcheck_fiat_shamir(tv, c, *pub[p], f_);
      const size_t a0 = A.size();
      const size_t n = Common::verifier_constraints(
          c, *pub[p], zk.proof[p], /*aux=*/nullptr, A, b, rows[p], tv,
          lay_.pad(p), f_, lay_.first(p));
      for (size_t k = a0; k < A.size(); ++k) A[k].c += cn;
      rows[p].c += cn;
      cn += n;
    }
    const LigeroTermSpan<Field> span{A.data(), A.size(), 0};
    const LigeroUnitSpan<Field> units{extra.a.data(), extra.a.size(), cn,
                                      extra.b.data()};
    cn += extra.b.size();
    check(cn == nrows && b.size() + extra.b.size() == nrows,
          "constraint rows");

    const char* why = "";
    const bool ok = LigeroVerifier<Field, RSFactory>::verify(
        &why, param_, zk.com, zk.com_proof, tv, cn, &span, 1, units, hash_of_A,
        b.data(), lqc_.data(), rsf_, f_, rows.data(), rows.size());
    log(INFO, "verify done: %s", why);
    return ok;
  }

 private:
  const ZkMultiLayout<Field>& lay_;
  const LigeroParam<Field> param_;
  const std::vector<LigeroQuadraticConstraint> lqc_;
  const RSFactory& rsf_;
  const Field& f_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ZK_ZK_MULTI_H_
