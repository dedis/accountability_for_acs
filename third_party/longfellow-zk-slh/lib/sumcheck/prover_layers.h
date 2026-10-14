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

#ifndef PRIVACY_PROOFS_ZK_LIB_SUMCHECK_PROVER_LAYERS_H_
#define PRIVACY_PROOFS_ZK_LIB_SUMCHECK_PROVER_LAYERS_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "arrays/affine.h"
#include "arrays/dense.h"
#include "arrays/eqs.h"
#include "arrays/packed_layer.h"
#include "sumcheck/circuit.h"
#include "sumcheck/equad.h"
#include "sumcheck/hquad.h"
#include "sumcheck/quad.h"
#include "sumcheck/transcript_sumcheck.h"
#include "util/panic.h"

namespace proofs {

// A high level idea is partially described in chapter 4.6.7 "Leveraging Data
// Parallelism for Further Speedups" in the book "Proofs, Arguments, and
// Zero-Knowledge" by Justin Thaler.
template <class Field>
class ProverLayers {
  using Elt = typename Field::Elt;

 public:
  using inputs = std::vector<std::unique_ptr<Dense<Field>>>;
  using PackedLayer = proofs::PackedLayer<Field>;

  explicit ProverLayers(const Field& f) : f_(f) {}

  // Evaluate CIRCUIT on input wires W0.  This function stores the
  // input wires of each layer L into IN->at(L), and returns the
  // final output.  This asymmetry reflects the fact that for L
  // layers there are L+1 meaningful sets of wires, and that the
  // prover needs IN while the verifier needs the final output.
  std::unique_ptr<Dense<Field>> eval_circuit(inputs* in,
                                             const Circuit<Field>* circ,
                                             std::unique_ptr<Dense<Field>> W0,
                                             const Field& F) {
    if (in == nullptr || circ == nullptr || W0 == nullptr) return nullptr;

    std::unique_ptr<Dense<Field>> finalV;
    size_t nl = circ->nl, nc = circ->nc;
    check(nl >= 1, "nl >= 1");
    check(nc >= 1, "nc >= 1");

    Dense<Field>* W = W0.get();

    in->resize(nl);
    in->at(nl - 1).swap(W0);

    // Allocate memory and evaluate layer on input W and output V
    for (size_t l = nl; l-- > 0;) {
      Dense<Field>* V;
      if (l > 0) {
        // input of layer l-1 = output of layer l
        in->at(l - 1) = std::make_unique<Dense<Field>>(nc, circ->l[l - 1].nw);
        V = in->at(l - 1).get();
      } else {
        // final output = output of layer 0
        finalV = std::make_unique<Dense<Field>>(nc, circ->nv);
        V = finalV.get();
      }

      bool ok = eval_quad(circ->l[l].quad.get(), V, W, F);
      if (!ok) {
        // Early exit in case of assertion failure.
        // In this case IN is only partially allocated.
        // To avoid ambiguities, free all memory that we may have allocated.
        for (size_t i = 0; i < nl; ++i) {
          in->at(i) = nullptr;
        }
        finalV = nullptr;

        return /*finalV=*/nullptr;
      }

      W = V;
    }

    return finalV;
  }

 protected:
  const Field& f_;

  // A struct that collects the bindings generated while proving one
  // layer, to serve as initial bindings for the next layer.
  // This protected class must be defined before the public section.
  struct bindings {
    size_t logv;
    Elt q[Proof<Field>::kMaxBindings];
    Elt g[2][Proof<Field>::kMaxBindings];
  };

  // Generate proof for circuit, as a protected member, the caller must
  // ensure that input parameters are valid.
  void prove(Proof<Field>* pr, const Proof<Field>* pad,
             const Circuit<Field>* circ, const inputs& in, ProofAux<Field>* aux,
             bindings& bnd, TranscriptSumcheck<Field>& ts, const Field& F) {
    auto run = [&](size_t ly, Eqs<Field>* EQ, HQuad<Field>* EQUAD) {
      layer(pr, pad, ts, bnd, ly, circ->logc, circ->l[ly].logw, EQ, EQUAD,
            in.at(ly).get(), F);
    };
    prove_layers(pr, pad, circ, run, aux, bnd, ts, F);
  }

  // eval_circuit() followed by prove(), with the wires stored packed (not
  // upstream), on the packed inputs W0, which the caller keeps. The input of
  // every layer is a PackedLayer: a wire that is 0
  // or 1 in every copy takes one bit per copy instead of one field element.
  // Each layer is evaluated from its packed input into a packed output, one
  // output wire at a time (eval_layer). The sumcheck computes the first copy
  // round from the packed input and binds it into a buffer of half the
  // copies, which holds the layer for the other rounds (layer_packed). The
  // proof is the same. Returns false if an assertion of the circuit fails or
  // an output is nonzero.
  bool prove_low_memory(Proof<Field>* pr, const Proof<Field>* pad,
                        const Circuit<Field>* circ, const PackedLayer& W0,
                        ProofAux<Field>* aux, bindings& bnd,
                        TranscriptSumcheck<Field>& ts, const Field& F) {
    const size_t nl = circ->nl;
    const corner_t nc = circ->nc;
    check(nl >= 1, "nl >= 1");
    check(nc >= 1, "nc >= 1");
    check(W0.n0() == nc, "input copies do not match the circuit");

    corner_t max_wires = std::max<corner_t>(circ->nv, W0.n1());
    size_t max_terms = 0;
    for (size_t l = 0; l < nl; ++l) {
      max_wires = std::max<corner_t>(max_wires, circ->l[l].nw);
      max_terms = std::max<size_t>(max_terms, circ->l[l].quad->size());
    }

    // Evaluation; its buffers are allocated once for all layers.
    std::vector<ecorner> terms(max_terms);
    std::vector<size_t> start(max_wires + 1);
    std::vector<Elt> row(nc);
    // in[l]: the input of layer l, l < nl - 1; W0 is the input of the last.
    std::vector<std::unique_ptr<PackedLayer>> in(nl);
    auto input = [&](size_t l) -> const PackedLayer& {
      return l + 1 == nl ? W0 : *in[l];
    };
    for (size_t l = nl; l-- > 0;) {
      const corner_t nv = l > 0 ? circ->l[l - 1].nw : circ->nv;
      std::unique_ptr<PackedLayer> out;
      if (l > 0) out = std::make_unique<PackedLayer>(nc, nv, F);
      if (!eval_layer(circ->l[l].quad.get(), nv, input(l), out.get(), terms,
                      start, row, F)) {
        return false;
      }
      if (l > 0) in[l - 1] = std::move(out);
    }

    // Sumcheck, with one buffer of half the copies and the EQ polynomials of
    // the pairs of copies.
    Dense<Field> work((nc + 1) / 2, max_wires);
    std::vector<CPoly> eqx((nc + 1) / 2);
    auto run = [&](size_t ly, Eqs<Field>* EQ, HQuad<Field>* EQUAD) {
      layer_packed(pr, pad, ts, bnd, ly, circ->logc, circ->l[ly].logw, EQ,
                   EQUAD, input(ly), &work, eqx, F);
      in[ly].reset();
    };
    prove_layers(pr, pad, circ, run, aux, bnd, ts, F);
    return true;
  }

  // The body of prove(). RUN(ly, EQ, EQUAD) proves layer LY (layer() or
  // layer_packed()); it is called for ly = 0, 1, ..., nl-1.
  template <class Run>
  void prove_layers(Proof<Field>* pr, const Proof<Field>* pad,
                    const Circuit<Field>* circ, const Run& run,
                    ProofAux<Field>* aux, bindings& bnd,
                    TranscriptSumcheck<Field>& ts, const Field& F) {
    size_t logc = circ->logc;
    corner_t nc = circ->nc;

    check(circ->logv <= Proof<Field>::kMaxBindings,
          "CIRCUIT->logv <= kMaxBindings");
    bnd.logv = circ->logv;

    // obtain the initial Q and G[0] bindings from the verifier
    ts.begin_circuit(bnd.q, bnd.g[0]);

    // Duplicate the g[0] binding.
    // In general, the prover step takes two claims G[0], G[1] on the output
    // wires and reduces them to one claim on G[0] + alpha * G[1] for random
    // alpha. However, in the first step, there is only one claim, so we
    // need to make up G[1]. The code sets G[1] = G[0] and it doesn't affect
    // soundness.
    for (size_t i = 0; i < bnd.logv; ++i) {
      bnd.g[1][i] = bnd.g[0][i];
    }

    for (size_t ly = 0; ly < circ->nl; ++ly) {
      auto clr = &circ->l.at(ly);
      Elt alpha, beta;
      ts.begin_layer(alpha, beta, ly);
      Eqs<Field> EQ(logc, nc, bnd.q, F);
      auto EQUAD =
          clr->quad->bind_g(bnd.logv, bnd.g[0], bnd.g[1], alpha, beta, F);

      run(ly, &EQ, EQUAD.get());

      if (aux != nullptr) {
        aux->bound_quad[ly] = EQUAD->scalar();
      }
    }
  }

  // Evaluate the quadratic form
  //
  //         V[g,c] = QUAD[g|r,l] W[r,c] W[l,c]
  //
  // Returns false in the case the quad is an assert0 check that fails.
  bool eval_quad(const Quad<Field>* quad, Dense<Field>* V,
                 const Dense<Field>* W, const Field& F) {
    check(V->n0_ == W->n0_, "V->n0_ == W->n0_");
    corner_t n0 = V->n0_;

    V->clear(F);
    for (const auto& ec : *quad) {
      const corner_t g(ec.g);
      const corner_t r(ec.h[0]);
      const corner_t l(ec.h[1]);
      for (corner_t c = 0; c < n0; ++c) {
        if (ec.v == F.zero()) {
          // assert that the computed W[l]W[r] is zero.
          Elt y = W->v_[n0 * l + c];
          F.mul(y, W->v_[n0 * r + c]);
          if (y != F.zero()) {
            return false;
          }
        } else {
          Elt x = ec.v;
          F.mul(x, W->v_[n0 * l + c]);
          F.mul(x, W->v_[n0 * r + c]);
          F.add(V->v_[n0 * g + c], x);
        }
      }
    }
    return true;
  }

  // The terms of a quad, with their coefficient.
  using ecorner = typename EQuad<Field>::ecorner;

  // V = QUAD(W) for the packed input W, by output wire (not upstream): the
  // terms are sorted by output wire into TERMS (counting sort; START[g] is
  // the first term of wire g), each output wire is accumulated in ROW, then
  // packed into OUT, or, if OUT is null (the circuit outputs), must be zero.
  // The values are those of eval_quad. When W[l] or W[r] is a bit wire, the
  // product W[l,c] W[r,c] is the other factor (or one) where the bit is set
  // and zero where it is not; it is selected, not multiplied. A coefficient
  // of one is not multiplied. The work and the branches depend only on which
  // wires are bit wires (the circuit structure), not on the bit values.
  // Returns false if an assertion fails or an output is nonzero.
  bool eval_layer(const Quad<Field>* quad, corner_t nv, const PackedLayer& W,
                  PackedLayer* out, std::vector<ecorner>& terms,
                  std::vector<size_t>& start, std::vector<Elt>& row,
                  const Field& F) {
    const corner_t n0 = W.n0();
    check(row.size() >= n0, "row buffer too small");
    check(terms.size() >= quad->size() && start.size() > nv,
          "term buffers too small");
    std::fill(start.begin(), start.begin() + nv + 1, 0);
    for (const auto& ec : *quad) {
      const corner_t g(ec.g);
      check(g < nv, "g < nv");
      ++start[g + 1];
    }
    for (corner_t g = 0; g < nv; ++g) start[g + 1] += start[g];
    for (const auto& ec : *quad) terms[start[corner_t(ec.g)]++] = ec;
    for (corner_t g = nv; g > 0; --g) start[g] = start[g - 1];
    start[0] = 0;

    const Elt zero = F.zero();
    Elt* Vg = &row[0];
    for (corner_t g = 0; g < nv; ++g) {
      std::fill(Vg, Vg + n0, zero);
      for (size_t t = start[g]; t < start[g + 1]; ++t) {
        if (!eval_term(terms[t], Vg, W, F)) return false;
      }
      if (out != nullptr) {
        out->set_wire(g, Vg);
      } else {
        for (corner_t c = 0; c < n0; ++c) {
          if (Vg[c] != zero) return false;
        }
      }
    }
    return true;
  }

  // Vg[c] += EC.v W[l,c] W[r,c] for all copies c, or, if EC.v is zero (an
  // assertion), false if some W[l,c] W[r,c] is nonzero. See eval_layer.
  bool eval_term(const ecorner& ec, Elt* Vg, const PackedLayer& W,
                 const Field& F) {
    const corner_t n0 = W.n0();
    const size_t words = W.words();
    const Elt zero = F.zero(), one = F.one();
    auto bit = [](const uint64_t* m, corner_t c) {
      return (m[c / 64] >> (c % 64)) & 1;
    };
    const corner_t r(ec.h[0]);
    const corner_t l(ec.h[1]);
    const bool assert0 = ec.v == zero, unit = ec.v == one;
    const uint64_t* a = W.bits(l);
    const uint64_t* b = W.bits(r);
    if (a != nullptr && b != nullptr) {
      // The product is the bit a & b.
      if (assert0) {
        uint64_t any = 0;
        for (size_t k = 0; k < words; ++k) any |= a[k] & b[k];
        return any == 0;
      }
      const Elt add[2] = {zero, ec.v};
      for (corner_t c = 0; c < n0; ++c) {
        F.add(Vg[c], add[bit(a, c) & bit(b, c)]);
      }
    } else if (a != nullptr || b != nullptr) {
      // The product is X where the bit is set, zero elsewhere.
      const uint64_t* m = a != nullptr ? a : b;
      const Elt* X = a != nullptr ? W.full(r) : W.full(l);
      bool nonzero = false;
      for (corner_t c = 0; c < n0; ++c) {
        const Elt pick[2] = {zero, X[c]};
        const Elt& x = pick[bit(m, c)];
        if (assert0) {
          nonzero |= x != zero;
        } else {
          F.add(Vg[c], unit ? x : F.mulf(ec.v, x));
        }
      }
      if (nonzero) return false;
    } else {
      const Elt* A = W.full(l);
      const Elt* B = W.full(r);
      bool nonzero = false;
      for (corner_t c = 0; c < n0; ++c) {
        const Elt x = F.mulf(A[c], B[c]);
        if (assert0) {
          nonzero |= x != zero;
        } else {
          F.add(Vg[c], unit ? x : F.mulf(ec.v, x));
        }
      }
      if (nonzero) return false;
    }
    return true;
  }

 private:
  using index_t = typename EQuad<Field>::index_t;
  using CPoly = typename LayerProof<Field>::CPoly;
  using WPoly = typename LayerProof<Field>::WPoly;
  using FCPoly = typename LayerProof<Field>::FCPoly;
  using FWPoly = typename LayerProof<Field>::FWPoly;
  using T2 = Poly<2, Field>;

  /*
  Engage in single-layer sumcheck on

          EQ[|c] QUAD[|r,l] W[r,c] W[l,c]

  Bind c to C, r to R, and l to L (in that order).  Store claims
  W[R,C] and W[L,C] in the proof, and set BND to the new bindings for
  the next layer.

  logw: number of sumcheck rounds in r, l
  logc: number of sumcheck rounds in c
  */
  void layer(Proof<Field>* pr, const Proof<Field>* pad,
             TranscriptSumcheck<Field>& ts, bindings& bnd, size_t layer,
             size_t logc, size_t logw, Eqs<Field>* EQ, HQuad<Field>* EQUAD,
             Dense<Field>* W, const Field& F, size_t first_round = 0) {
    check(EQ->n() == W->n0_, "EQ->n() == W->n0_");

    check(logw <= Proof<Field>::kMaxBindings, "logw <= kMaxBindings");
    check(logc <= Proof<Field>::kMaxBindings, "logc <= kMaxBindings");
    bnd.logv = logw;

    // Bind the C variables to Q.
    // Note that binding C variables takes O(number_of_copies * circuit_size)
    // while binding R, L takes O(circuit_size * log(circuit_size)). In most
    // cases number_of_copies > log(circuit_size), so we don't have to
    // optimize binding R, L.
    // Rounds before FIRST_ROUND were run by layer_packed() (not upstream).
    for (size_t round = first_round; round < logc; ++round) {
      CPoly sum{};

      // sum over r,l: QUAD[|r,l] EQ[|c] W[r,c] W[l,c]
      for (index_t i = 0; i < EQUAD->n_; i++) {
        const corner_t r(EQUAD->hc_[i].h[0]);
        const corner_t l(EQUAD->hc_[i].h[1]);

        // sum over c: EQ[|c] W[r,c] W[l,c]
        CPoly sumc{};

        // n0_ is the copy dimension, n1_ is the wire dimension.
        for (corner_t c = 0; c < W->n0_; c += 2) {
          const CPoly poly = cpoly_at_dense(EQ, c, 0, F)
                                 .mul(cpoly_at_dense(W, c, r, F), F)
                                 .mul(cpoly_at_dense(W, c, l, F), F);
          sumc.add(poly, F);
        }

        sumc.mul_scalar(EQUAD->vc_[i].v, F);
        sum.add(sumc, F);
      }

      Elt rnd = round_c(pr, pad, ts, layer, round, sum, F);
      bnd.q[round] = rnd;

      // bind the c variable in both EQ and W
      EQ->bind(rnd, F);
      W->bind(rnd, F);
    }

    Elt eq0 = EQ->scalar();

    W->reshape(W->n1_);
    check(W->n1_ == 1, "W->n1_ == 1");

    // To save memory, we avoid cloning W. Instead, we use a single temporary
    // buffer Wtmp of size N/2 and start with both hand-pointers WH[0,1]
    // pointing to W. In the first round of the loop, hand 0 is bound
    // out-of-place from W into Wtmp, and we then update WH[0] to point to Wtmp.
    // Hand 1 is then bound in-place in W. This strategy uses 1.5N space instead
    // of 2N.
    auto Wtmp = std::make_unique<Dense<Field>>((W->n0_ + 1) / 2, 1);
    Dense<Field>* WH[2] = {W, W};

    // QW has at most W->n0_ elements; one allocation for all rounds (not
    // upstream).
    Dense<Field> QW(W->n0_, 1);

    for (size_t round = 0; round < logw; ++round) {
      for (size_t hand = 0; hand < 2; hand++) {
        // In SUM_{l,r} Q[l,r] W[l] W[r], first precompute QW[l] =
        // SUM_{r} Q[l,r] W[r] as a dense array, and then compute
        // SUM_{l} QW[l] W[l].
        QW.n0_ = WH[hand]->n0_;
        QW.clear(F);
        size_t ohand = 1 - hand;

        // QW[l] = SUM_{r} Q[l,r] W[r]
        for (index_t i = 0; i < EQUAD->n_; ++i) {
          const corner_t p0(EQUAD->hc_[i].h[hand]);
          const corner_t p1(EQUAD->hc_[i].h[ohand]);
          F.add(QW.v_[p0], F.mulf(EQUAD->vc_[i].v, WH[ohand]->v_[p1]));
        }

        // SUM_{l} QW[l] W[l].
        WPoly sum{};
        for (corner_t l = 0; l < QW.n0_; l += 2) {
          WPoly poly = wpoly_at_dense(WH[hand], l, 0, F)
                           .mul(wpoly_at_dense(&QW, l, 0, F), F);
          sum.add(poly, F);
        }

        sum.mul_scalar(eq0, F);
        Elt rnd = round_h(pr, pad, ts, layer, hand, round, sum, F);
        bnd.g[hand][round] = rnd;

        // bind the r variable in W[hand] and QUAD
        if (round == 0 && hand == 0) {
          WH[0] = Wtmp.get();
          WH[0]->bind(rnd, *W, F);
        } else {
          WH[hand]->bind(rnd, F);
        }
        EQUAD->bind_h(rnd, hand, F);
      }
    }

    EQUAD->scalar();  // for the side effect of assertions
    Elt WC[2] = {WH[0]->scalar(), WH[1]->scalar()};
    end_layer(pr, pad, ts, layer, WC, F);
  }


  // layer() for the packed input W (not upstream). The first copy round
  // reads the packed wires, and its binding writes the layer, with half the
  // copies, into WORK; the other rounds run on WORK (layer()). In the first
  // round, a pair of copies c, c + 1 contributes EQ(X) W[r](X) W[l](X) to a
  // term. When both wires are bit wires, W[r](X) W[l](X) depends only on the
  // four bits, so the round adds EQ(X) (EQX[pair], computed once per layer)
  // into one of 16 classes and multiplies once per class. Each bit wire is
  // bound by a table of the 4 values of a pair. Same polynomials and values
  // as layer().
  void layer_packed(Proof<Field>* pr, const Proof<Field>* pad,
                    TranscriptSumcheck<Field>& ts, bindings& bnd, size_t ly,
                    size_t logc, size_t logw, Eqs<Field>* EQ,
                    HQuad<Field>* EQUAD, const PackedLayer& W,
                    Dense<Field>* work, std::vector<CPoly>& eqx,
                    const Field& F) {
    if (logc == 0) {
      W.unpack(*work);
      layer(pr, pad, ts, bnd, ly, logc, logw, EQ, EQUAD, work, F);
      return;
    }
    const corner_t n0 = W.n0();
    const corner_t npairs = (n0 + 1) / 2;
    check(EQ->n() == n0, "EQ->n() == W.n0()");
    check(eqx.size() >= npairs, "eqx too small");
    check(work->v_.size() >= npairs * W.n1(), "work buffer too small");
    for (corner_t p = 0; p < npairs; ++p) {
      eqx[p] = cpoly_at_dense(EQ, 2 * p, 0, F);
    }

    const Elt value[2] = {F.zero(), F.one()};
    // The values of wire I at copies C and C + 1 (zero past the last copy).
    auto pair = [&](corner_t i, corner_t c) {
      if (const uint64_t* b = W.bits(i)) {
        return T2{value[(b[c / 64] >> (c % 64)) & 1],
                  value[(b[c / 64] >> (c % 64 + 1)) & 1]};
      }
      const Elt* x = W.full(i);
      return T2{x[c], c + 1 < n0 ? x[c + 1] : F.zero()};
    };
    // PROD[k] = W[r](X) W[l](X) for the bits k = r0 | r1 << 1 | l0 << 2 |
    // l1 << 3 of a pair.
    CPoly prod[16];
    for (size_t k = 0; k < 16; ++k) {
      prod[k] = CPoly(FCPoly::extend(T2{value[k & 1], value[(k >> 1) & 1]}, F));
      prod[k].mul(CPoly(FCPoly::extend(
                      T2{value[(k >> 2) & 1], value[(k >> 3) & 1]}, F)),
                  F);
    }

    CPoly sum{};
    for (index_t i = 0; i < EQUAD->n_; ++i) {
      const corner_t r(EQUAD->hc_[i].h[0]);
      const corner_t l(EQUAD->hc_[i].h[1]);
      const uint64_t* br = W.bits(r);
      const uint64_t* bl = W.bits(l);
      CPoly sumc{};
      if (br != nullptr && bl != nullptr) {
        CPoly cls[16] = {};
        for (corner_t p = 0; p < npairs; ++p) {
          const corner_t c = 2 * p;  // c and c + 1 are in one word
          const size_t k = ((br[c / 64] >> (c % 64)) & 3) |
                           (((bl[c / 64] >> (c % 64)) & 3) << 2);
          cls[k].add(eqx[p], F);
        }
        for (size_t k = 0; k < 16; ++k) {
          CPoly t = prod[k];
          sumc.add(t.mul(cls[k], F), F);
        }
      } else {
        for (corner_t p = 0; p < npairs; ++p) {
          CPoly poly = eqx[p];
          poly.mul(CPoly(FCPoly::extend(pair(r, 2 * p), F)), F)
              .mul(CPoly(FCPoly::extend(pair(l, 2 * p), F)), F);
          sumc.add(poly, F);
        }
      }
      sumc.mul_scalar(EQUAD->vc_[i].v, F);
      sum.add(sumc, F);
    }

    const Elt rnd = round_c(pr, pad, ts, ly, 0, sum, F);
    bnd.q[0] = rnd;
    EQ->bind(rnd, F);

    // Bind the first copy variable: WORK[w, p] = W[w, 2p] + rnd (W[w, 2p + 1]
    // - W[w, 2p]), with W[w, n0] = 0.
    work->n0_ = npairs;
    work->n1_ = W.n1();
    Elt bound[4];
    for (size_t k = 0; k < 4; ++k) {
      bound[k] = affine_interpolation(rnd, value[k & 1], value[k >> 1], F);
    }
    for (corner_t i = 0; i < W.n1(); ++i) {
      Elt* x = &work->v_[npairs * i];
      if (const uint64_t* b = W.bits(i)) {
        for (corner_t p = 0; p < npairs; ++p) {
          const corner_t c = 2 * p;
          x[p] = bound[(b[c / 64] >> (c % 64)) & 3];
        }
      } else {
        const Elt* f = W.full(i);
        for (corner_t p = 0; p < npairs; ++p) {
          const corner_t c = 2 * p;
          x[p] = c + 1 < n0 ? affine_interpolation(rnd, f[c], f[c + 1], F)
                            : affine_interpolation_nz_z(rnd, f[c], F);
        }
      }
    }
    layer(pr, pad, ts, bnd, ly, logc, logw, EQ, EQUAD, work, F,
          /*first_round=*/1);
  }

  Elt /*R*/ round_c(Proof<Field>* pr, const Proof<Field>* pad,
                    TranscriptSumcheck<Field>& ts, size_t layer, size_t round,
                    CPoly poly, const Field& F) {
    check(round < Proof<Field>::kMaxBindings, "round < kMaxBindings");

    if (pad) {
      poly.sub(pad->l[layer].cp[round], F);
    }

    pr->l[layer].cp[round] = poly;
    return ts.round(poly);
  }

  Elt /*R*/ round_h(Proof<Field>* pr, const Proof<Field>* pad,
                    TranscriptSumcheck<Field>& ts, size_t layer, size_t hand,
                    size_t round, WPoly poly, const Field& F) {
    check(round < Proof<Field>::kMaxBindings, "round < kMaxBindings");
    if (pad) {
      poly.sub(pad->l[layer].hp[hand][round], F);
    }
    pr->l[layer].hp[hand][round] = poly;
    return ts.round(poly);
  }

  void end_layer(Proof<Field>* pr, const Proof<Field>* pad,
                 TranscriptSumcheck<Field>& ts, size_t layer, const Elt wc[2],
                 const Field& F) {
    Elt tt[2] = {wc[0], wc[1]};
    if (pad) {
      F.sub(tt[0], pad->l[layer].wc[0]);
      F.sub(tt[1], pad->l[layer].wc[1]);
    }

    pr->l[layer].wc[0] = tt[0];
    pr->l[layer].wc[1] = tt[1];

    ts.write(tt, 1, 2);
  }

  CPoly cpoly_at_dense(const Dense<Field>* D, corner_t p0, corner_t p1,
                       const Field& F) {
    auto tmp = FCPoly::extend(D->t2_at_corners(p0, p1, F), F);
    return CPoly(tmp);
  }

  WPoly wpoly_at_dense(const Dense<Field>* D, corner_t p0, corner_t p1,
                       const Field& F) {
    auto tmp = FWPoly::extend(D->t2_at_corners(p0, p1, F), F);
    return WPoly(tmp);
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_SUMCHECK_PROVER_LAYERS_H_
