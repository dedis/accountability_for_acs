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

#ifndef PRIVACY_PROOFS_ZK_LIB_ZK_ZK_PROVER_H_
#define PRIVACY_PROOFS_ZK_LIB_ZK_ZK_PROVER_H_

#include <stddef.h>

#include <memory>
#include <vector>

#include "arrays/dense.h"
#include "arrays/packed_layer.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_prover.h"
#include "random/random.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/prover_layers.h"
#include "sumcheck/transcript_sumcheck.h"
#include "util/log.h"
#include "util/panic.h"
#include "zk/zk_common.h"
#include "zk/zk_proof.h"

namespace proofs {
// ZK Prover
//
// This class implements a zero-knowledge argument over a sumcheck transcript
// by first committing to a sumcheck witness and a random pad to encrypt
// a sumcheck transcript, then running the sumcheck protocol over the original
// claim and witness, but outputting the encrypted transcript, and finally
// using a Ligero prover to prove the statement: "the committed witness and
// pad, when used to decrypt the encrypted sumcheck transcript satisfies the
// sumcheck verifier."
//
// While this statement is complex, it can be implemented easily because
// the sumcheck verifier essentially checks the evaluations of degree-2 or -3
// polynomials, and performs one multiplication per layer of the circuit. The
// Hyrax paper makes a similar observation, but uses an elliptic-curve based
// proof, whereas here we use the Ligero system.
template <class Field, class ReedSolomonFactory>
class ZkProver : public ProverLayers<Field> {
  using super = ProverLayers<Field>;
  using typename super::bindings;
  using Elt = typename Field::Elt;
  using typename super::inputs;

 public:
  ZkProver(const Circuit<Field>& CIRCUIT, const Field& F,
           const ReedSolomonFactory& rs_factory)
      : ProverLayers<Field>(F),
        c_(CIRCUIT),
        n_witness_(ZkCommon<Field>::num_witness(c_)),
        f_(F),
        rsf_(rs_factory),
        pad_(c_.nl),
        lqc_(c_.nl),
        lp_(nullptr) {}

  void commit(ZkProof<Field>& zkp, const Dense<Field>& W, Transcript& tp,
              RandomEngine& rng) {
    commit(zkp, PackedLayer<Field>(W, f_), tp, rng);
  }

  // Not upstream: commits to the private inputs of W, read in place from
  // the packed inputs (no copy of the witness), and to the pad.
  void commit(ZkProof<Field>& zkp, const PackedLayer<Field>& W, Transcript& tp,
              RandomEngine& rng) {
    log(INFO, "ZK Commit start");
    check(W.n0() == c_.nc && W.n1() == c_.ninputs,
          "inputs do not match the circuit");

    // Rebase the circuit SUBFIELD_BOUNDARY (if any) to start at
    // NPUB_IN, for all copies.
    size_t subfield_boundary = 0;
    if (c_.subfield_boundary >= c_.npub_in) {
      subfield_boundary = (c_.subfield_boundary - c_.npub_in) * c_.nc;
    }

    // Fill pad with random values, record lqc.
    std::vector<Elt> pad;
    pad.reserve(ZkCommon<Field>::pad_size(c_));
    fill_pad(rng, pad);
    ZkCommon<Field>::setup_lqc(c_, lqc_, n_witness_ /* = start_pad */);

    // Commit to witness and pad. Layout of the com:
    // 0 ...<witnesses>... start_pad <pad> len. W holds input I of copy C at
    // nc * I + C, so the private inputs of all copies are contiguous from
    // npub_in * nc (ZkCommon::witness_index).
    const Committed committed{W, c_.npub_in * c_.nc, n_witness_, pad};
    lp_ = std::make_unique<LigeroProver<Field, ReedSolomonFactory>>(zkp.param);
    lp_->commit(zkp.com, tp, committed, subfield_boundary, &lqc_[0], rsf_,
                rng, f_);

    log(INFO, "ZK Commitment done");
  }

  // EXTRA: optional statement constraints on the private witness
  // (ZkCommon::ExtraConstraints, not upstream).
  bool prove(ZkProof<Field>& zkp, const Dense<Field>& W, Transcript& tsp,
             const typename ZkCommon<Field>::ExtraConstraints* extra =
                 nullptr) {
    return prove(zkp, PackedLayer<Field>(W, f_), tsp, extra);
  }

  // Not upstream: proves from the packed inputs W, which commit() received.
  // The public inputs are read from W.
  bool prove(ZkProof<Field>& zkp, const PackedLayer<Field>& W,
             Transcript& tsp,
             const typename ZkCommon<Field>::ExtraConstraints* extra =
                 nullptr) {
    // One prove per commit: a second one would reuse the pads (not
    // upstream).
    check(lp_ != nullptr, "must run commit before prove");
    const auto lp = std::move(lp_);
    check(W.n0() == c_.nc && W.n1() == c_.ninputs,
          "inputs do not match the circuit");
    if (extra != nullptr && !ZkCommon<Field>::extra_valid(*extra, c_)) {
      log(ERROR, "extra constraint index out of range");
      return false;
    }

    // Interpret W as public parameters, we only append
    // c_.npub_in elements of W to the transcript
    ZkCommon<Field>::initialize_sumcheck_fiat_shamir(tsp, c_, W, f_);
    Transcript tst = tsp.clone();

    // Run sumcheck to generate a padded proof, keeping few layers of wires
    // (ProverLayers::prove_low_memory; not upstream).
    bindings bnd;
    ProofAux<Field> aux(c_.nl);
    TranscriptSumcheck<Field> tsts(tst, f_);
    if (!super::prove_low_memory(&zkp.proof, &pad_, &c_, W, &aux, bnd, tsts,
                                 f_)) {
      log(ERROR, "circuit evaluation failed or an output is nonzero");
      return false;
    }
    log(INFO, "ZK sumcheck done");

    // 5. Simulate the verifier to assemble constraints on the committed vals.
    //    Form the sparse matrix A and vector b such that A*w = b.
    std::vector<LigeroLinearConstraint<Field>> a;
    std::vector<Elt> b;
    LigeroProductRow<Field> row;
    a.reserve(ZkCommon<Field>::num_terms(c_) +
              (extra != nullptr ? extra->a.size() : 0));
    b.reserve(c_.nl + 1);
    size_t ci = ZkCommon<Field>::verifier_constraints(
        c_, W, zkp.proof, &aux, a, b, row, tsp, n_witness_, f_);
    if (extra != nullptr) {
      for (const auto& e : extra->a) {
        a.push_back(LigeroLinearConstraint<Field>{ci + e.c, e.w, e.k});
      }
      ci += extra->b.size();
    }
    log(INFO, "ZK constraints done");

    // 6. Produce proof over commitment.
    // For FS soundness, it is ok for hash_of_A to be any string.
    // In the interactive version, the verifier provides a challenge for the
    // com proof. The last prover message is the (wc_l,wc_r) pair, and this
    // has already been added to the transcript.
    // The sumcheck constraints follow from the transcript; the extra ones
    // are bound by their hash.
    const LigeroHash hash_of_A =
        extra != nullptr ? ZkCommon<Field>::extra_hash(*extra, f_)
                         : LigeroHash{0xde, 0xad, 0xbe, 0xef};
    lp->prove(zkp.com_proof, tsp, ci, a.size(), &a[0], hash_of_A, &lqc_[0],
              rsf_, f_, &row);

    log(INFO, "Prover Done: flag");
    return true;
  }

  // Fill proof with random pad values for a given circuit. PAD receives the
  // committed pad elements (not upstream).
  void fill_pad(RandomEngine& rng, std::vector<Elt>& pad) {
    for (size_t i = 0; i < c_.nl; ++i) {
      for (size_t j = 0; j < c_.logc; ++j) {
        for (size_t k = 0; k < 4; ++k) {
          if (k != 1) {  // P(1) optimization
            Elt r = rng.elt(f_);
            pad_.l[i].cp[j].t_[k] = r;
            pad.push_back(r);
          } else {
            pad_.l[i].cp[j].t_[k] = f_.zero();
          }
        }
      }
      for (size_t j = 0; j < c_.l[i].logw; ++j) {
        for (size_t h = 0; h < 2; ++h) {
          for (size_t k = 0; k < 3; ++k) {
            if (k != 1) {  // P(1) optimization
              Elt r = rng.elt(f_);
              pad_.l[i].hp[h][j].t_[k] = r;
              pad.push_back(r);
            } else {
              pad_.l[i].hp[h][j].t_[k] = f_.zero();
            }
          }
        }
      }
      for (size_t k = 0; k < 2; ++k) {
        Elt r = rng.elt(f_);
        pad_.l[i].wc[k] = r;
        pad.push_back(r);
      }

      // Commit to product of pads for product proof.
      Elt rr = f_.mulf(pad_.l[i].wc[0], pad_.l[i].wc[1]);
      pad.push_back(rr);
    }
  }

  const Circuit<Field>& c_;
  const size_t n_witness_;
  const Field& f_;
  const ReedSolomonFactory& rsf_;
  Proof<Field> pad_;

  // The committed vector (not upstream): the private inputs of all copies,
  // read from the packed inputs in the layout of Dense, then the pad.
  struct Committed {
    const PackedLayer<Field>& w;
    size_t first, n_witness;
    const std::vector<Elt>& pad;
    Elt operator[](size_t j) const {
      return j < n_witness ? w.at(first + j) : pad[j - n_witness];
    }
  };
  std::vector<LigeroQuadraticConstraint> lqc_;
  std::unique_ptr<LigeroProver<Field, ReedSolomonFactory>> lp_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ZK_ZK_PROVER_H_
