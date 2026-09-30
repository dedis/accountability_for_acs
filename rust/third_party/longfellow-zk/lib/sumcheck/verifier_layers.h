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

#ifndef PRIVACY_PROOFS_ZK_LIB_SUMCHECK_VERIFIER_LAYERS_H_
#define PRIVACY_PROOFS_ZK_LIB_SUMCHECK_VERIFIER_LAYERS_H_

#include <stddef.h>

#include <cstddef>

#include "arrays/affine.h"
#include "arrays/eq.h"
#include "sumcheck/circuit.h"
#include "sumcheck/quad.h"
#include "sumcheck/transcript_sumcheck.h"
#include "util/panic.h"

namespace proofs {
// Sumcheck verifier that only verifies the layers.
// Derived classes are responsible for verifying the
// input binding, either directly or through a commitment.
template <class Field>
class VerifierLayers {
 public:
  typedef typename Quad<Field>::index_t index_t;
  using Elt = typename Field::Elt;

  struct claims {
    corner_t nv;
    size_t logv;
    Elt claim[2];
    const Elt* q;
    const Elt* g[2];
  };
  // Verify all the circuit layers, returning claims on the inputs in
  // CL.  The caller is responsible to verify the claims, either via
  // direct check or polynomial commitment.
  static bool circuit(const char** why, claims* cl,
                      const Circuit<Field>* CIRCUIT, const Proof<Field>* PROOF,
                      Challenge<Field>* CH, TranscriptSumcheck<Field>& ts,
                      const Field& F) {
    if (why == nullptr || cl == nullptr || CIRCUIT == nullptr ||
        PROOF == nullptr || CH == nullptr) {
      return false;
    }
    *why = "ok";

    ts.begin_circuit(CH->q, CH->g);

    *cl = claims{
        .nv = CIRCUIT->nv,
        .logv = CIRCUIT->logv,
        .claim = {F.zero(), F.zero()},
        .q = CH->q,
        .g = {CH->g, CH->g},
    };

    return layers(why, cl, CIRCUIT, PROOF, ts, CH, F);
  }

  VerifierLayers() = delete;

 private:
  struct desire {
    bool cond;
    const char* why;
  };

  static bool check(const char** why, size_t n, const desire* d) {
    for (size_t i = 0; i < n; ++i) {
      if (!d[i].cond) {
        *why = d[i].why;
        return false;
      }
    }
    return true;
  }

  // Verify CLAIM for one layer and update CLAIM in-place as next
  // claim.  Return TRUE on success, and (FALSE, why) on failure.
  static bool layer_c(const char** why, Elt* claim, size_t logc,
                      const LayerProof<Field>* plr, LayerChallenge<Field>* ch,
                      TranscriptSumcheck<Field>& ts, const Field& F) {
    proofs::check(logc <= Proof<Field>::kMaxBindings, "logc <= kMaxBindings");
    for (size_t round = 0; round < logc; ++round) {
      // Change verification equation from
      //    claim =? (p(0) + p(1))
      // to p(1) = claim - p(0).
      auto tp = plr->cp[round];
      auto t1 = F.subf(*claim, tp.t_[0]);
      ch->cb[round] = ts.round(plr->cp[round]);
      auto p = tp.to_poly(t1);
      *claim = p.eval_lagrange(ch->cb[round], F);
    }

    return true;
  }

  static bool layer_h(const char** why, Elt* claim, size_t logw,
                      const LayerProof<Field>* plr, LayerChallenge<Field>* ch,
                      TranscriptSumcheck<Field>& ts, const Field& F) {
    proofs::check(logw <= Proof<Field>::kMaxBindings, "logw <= kMaxBindings");
    for (size_t round = 0; round < logw; ++round) {
      for (size_t hand = 0; hand < 2; ++hand) {
        // Change verification equation from
        //    claim =? (p(0) + p(1))
        // to p(1) = claim - p(0).
        auto tp = plr->hp[hand][round];
        auto t1 = F.subf(*claim, tp.t_[0]);
        ch->hb[hand][round] = ts.round(tp);
        auto p = tp.to_poly(t1);
        *claim = p.eval_lagrange(ch->hb[hand][round], F);
      }
    }
    return true;
  }

  // Verify CLAIMS for all layers and update CLAIMS in-place.  Return
  // TRUE on success, and (FALSE, why) on failure.
  static bool layers(const char** why, claims* cl,
                     const Circuit<Field>* CIRCUIT, const Proof<Field>* PROOF,
                     TranscriptSumcheck<Field>& ts, Challenge<Field>* CH,
                     const Field& F) {
    for (size_t ly = 0; ly < CIRCUIT->nl; ++ly) {
      auto clr = &CIRCUIT->l.at(ly);
      auto plr = &PROOF->l[ly];
      auto challenge = &CH->l[ly];

      // the claim is then an affine combination of the two
      // inductive claims
      ts.begin_layer(challenge->alpha, challenge->beta, ly);
      Elt claim = F.addf(cl->claim[0], F.mulf(challenge->alpha, cl->claim[1]));

      if (!layer_c(why, &claim, CIRCUIT->logc, plr, challenge, ts, F)) {
        return false;
      }

      if (!layer_h(why, &claim, clr->logw, plr, challenge, ts, F)) {
        return false;
      }

      // Now verify CLAIM = EQ[Q,C] QUAD[R,L] W[R,C] W[L,C]
      // where W[R,C], W[L,C] are in the proof.

      // bind QUAD[g|r,l] to the alpha-combination of the
      // two G values GR, GL
      auto EQUAD = clr->quad->bind_g(cl->logv, cl->g[0], cl->g[1],
                                     challenge->alpha, challenge->beta, F);

      // bind QUAD[G|r,l] to R, L
      proofs::check(clr->logw <= Proof<Field>::kMaxBindings,
                    "clr->logw <= kMaxBindings");
      for (size_t round = 0; round < clr->logw; ++round) {
        for (size_t hand = 0; hand < 2; ++hand) {
          EQUAD->bind_h(challenge->hb[hand][round], hand, F);
        }
      }

      // got = EQ[Q,C] QUAD[G|R,L] W[R,C] W[L,C], where
      // W[.,C] is in the proof.
      Elt got =
          Eq<Field>::eval(CIRCUIT->logc, CIRCUIT->nc, cl->q, challenge->cb, F);
      F.mul(got, EQUAD->scalar());
      F.mul(got, plr->wc[0]);
      F.mul(got, plr->wc[1]);

      if (got != claim) {
        *why = "got != claim (layer)";
        return false;
      }

      // Add wc[0,1] to transcript
      ts.write(&plr->wc[0], 1, 2);

      // Reduce to two claims on W[R,C] and W[L,C]
      *cl = claims{
          .nv = clr->nw,
          .logv = clr->logw,
          .claim = {plr->wc[0], plr->wc[1]},
          .q = challenge->cb,
          .g = {challenge->hb[0], challenge->hb[1]},
      };
    }
    return true;
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_SUMCHECK_VERIFIER_LAYERS_H_
