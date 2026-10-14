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

#ifndef PRIVACY_PROOFS_ZK_LIB_ZK_ZK_VERIFIER_H_
#define PRIVACY_PROOFS_ZK_LIB_ZK_ZK_VERIFIER_H_

#include <stddef.h>

#include <vector>

#include "arrays/dense.h"
#include "arrays/packed_layer.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_verifier.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "zk/zk_common.h"
#include "zk/zk_proof.h"

namespace proofs {
// ZK Verifier
//
// Verifies a zk proof. See note in the prover for the design.
// To verify a proof, instantiate the class, then call recv_commitment with
// the commitment, and finally call verify. It is possible to receive several
// commitments, or run other protocols between the recv_commitment and verify
// calls. This allows composing two proofs in parallel.
// To support this, the interface to both accepts a raw Transcript.
template <class Field, class RSFactory>
class ZkVerifier {
  using Elt = typename Field::Elt;

 public:
  explicit ZkVerifier(const Circuit<Field>& c, const RSFactory& rsf,
                      size_t rate, size_t nreq, const Field& F)
      : circ_(c),
        n_witness_(ZkCommon<Field>::num_witness(c)),
        param_(n_witness_ + ZkCommon<Field>::pad_size(c), c.nl, rate, nreq),
        lqc_(c.nl),
        rsf_(rsf),
        f_(F) {
    ZkCommon<Field>::setup_lqc(c, lqc_, n_witness_);
  }

  explicit ZkVerifier(const Circuit<Field>& c, const RSFactory& rsf,
                      size_t rate, size_t nreq, size_t block_enc,
                      const Field& F)
      : circ_(c),
        n_witness_(ZkCommon<Field>::num_witness(c)),
        param_(n_witness_ + ZkCommon<Field>::pad_size(c), c.nl, rate, nreq,
               block_enc),
        lqc_(c.nl),
        rsf_(rsf),
        f_(F) {
    ZkCommon<Field>::setup_lqc(c, lqc_, n_witness_);
  }

  static size_t copies(const Dense<Field>& d) { return d.n0_; }
  static size_t wires(const Dense<Field>& d) { return d.n1_; }
  static size_t copies(const PackedLayer<Field>& d) { return d.n0(); }
  static size_t wires(const PackedLayer<Field>& d) { return d.n1(); }

  void recv_commitment(const ZkProof<Field>& zk, Transcript& t) const {
    log(INFO, "verifier: recv commit");
    LigeroVerifier<Field, RSFactory>::receive_commitment(zk.com, t);
  }

  // Verifies the proof. PUB holds exactly the public inputs of every copy
  // (npub_in wires), in the prover's Dense layout: a Dense or a PackedLayer
  // (not upstream). EXTRA: the statement constraints the prover used (not
  // upstream).
  template <class Pub>
  bool verify(const ZkProof<Field>& zk, const Pub& pub, Transcript& tv,
              const typename ZkCommon<Field>::ExtraConstraints* extra =
                  nullptr) const {
    log(INFO, "verifier: verify");
    if (copies(pub) != circ_.nc || wires(pub) != circ_.npub_in) {
      log(INFO, "verifier: public inputs do not match the circuit copies");
      return false;
    }
    if (extra != nullptr && !ZkCommon<Field>::extra_valid(*extra, circ_)) {
      log(INFO, "verifier: extra constraint index out of range");
      return false;
    }

    ZkCommon<Field>::initialize_sumcheck_fiat_shamir(tv, circ_, pub, f_);

    const LigeroHash hash_of_A =
        extra != nullptr ? ZkCommon<Field>::extra_hash(*extra, f_)
                         : LigeroHash{0xde, 0xad, 0xbe, 0xef};
    const size_t nrows = circ_.nl + 1 + (extra != nullptr ? extra->b.size() : 0);

    // Not upstream: check the Merkle openings on a copy of the transcript
    // first, so that a bad commitment or opening is rejected before the
    // constraint list (up to 2 GB) is built.
    {
      Transcript probe = tv.clone();
      ZkCommon<Field>::replay_sumcheck(circ_, zk.proof, probe, f_);
      if (!LigeroVerifier<Field, RSFactory>::check_openings(
              param_, zk.com, zk.com_proof, probe, nrows, hash_of_A, f_)) {
        log(INFO, "verifier: merkle_check failed");
        return false;
      }
    }

    // Derive constraints on the witness.
    using Llc = LigeroLinearConstraint<Field>;
    std::vector<Llc> A;
    std::vector<Elt> b;
    A.reserve(ZkCommon<Field>::num_terms(circ_) +
              (extra != nullptr ? extra->a.size() : 0));
    b.reserve(circ_.nl + 1 + (extra != nullptr ? extra->b.size() : 0));
    LigeroProductRow<Field> row;
    size_t cn = ZkCommon<Field>::verifier_constraints(
        circ_, pub, zk.proof, /*aux=*/nullptr, A, b, row, tv, n_witness_, f_);
    if (extra != nullptr) {
      for (const auto& e : extra->a) {
        A.push_back(Llc{cn + e.c, e.w, e.k});
      }
      b.insert(b.end(), extra->b.begin(), extra->b.end());
      cn += extra->b.size();
    }
    check(cn == nrows, "constraint rows");

    const char* why = "";
    bool ok = LigeroVerifier<Field, RSFactory>::verify(
        &why, param_, zk.com, zk.com_proof, tv, cn, A.size(), &A[0], hash_of_A,
        &b[0], &lqc_[0], rsf_, f_, &row);

    log(INFO, "verify done: %s", why);
    return ok;
  }

 private:
  const Circuit<Field>& circ_;
  const size_t n_witness_;
  const LigeroParam<Field> param_;
  std::vector<LigeroQuadraticConstraint> lqc_;
  const RSFactory& rsf_;
  const Field& f_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ZK_ZK_VERIFIER_H_
