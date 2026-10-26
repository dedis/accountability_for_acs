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
#include <utility>
#include <vector>

#include "algebra/base_coordinates.h"
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

 private:
  using Coords = BaseCoordinates<Field>;
  using Mac = MacOf<Field>;

 public:

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
    Elt wc[2];  // W[R,C] and W[L,C] of the last layer, without pad (not
                // upstream)
  };

  // Generate proof for circuit, as a protected member, the caller must
  // ensure that input parameters are valid.
  void prove(Proof<Field>* pr, const Proof<Field>* pad,
             const Circuit<Field>* circ, const inputs& in, ProofAux<Field>* aux,
             bindings& bnd, TranscriptSumcheck<Field>& ts, const Field& F) {
    auto run = [&](size_t ly, Eqs<Field>* EQ, HQuad<Field>* EQUAD,
                   const Elt& /*alpha*/) {
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
  // output wire at a time (eval_layer). The sumcheck computes the first two
  // copy rounds from the packed input and binds them into a buffer of a
  // quarter of the copies, which holds the layer for the other rounds
  // (layer_packed). The proof is the same. Returns false if an assertion of
  // the circuit fails or an output is nonzero.
  //
  // Not upstream: the layers are checkpointed. The first evaluation keeps
  // only the inputs of the layers LY with LY % STRIDE == 0; when the
  // sumcheck reaches a segment of STRIDE layers, the segment is evaluated
  // again from the checkpoint below it. Peak layer storage is about
  // nl / STRIDE + STRIDE layers instead of nl, for one more evaluation of
  // every layer; the values, and so the proof, are the same. STRIDE = 0
  // takes ceil(sqrt(nl)); STRIDE = 1 keeps every layer.
  bool prove_low_memory(Proof<Field>* pr, const Proof<Field>* pad,
                        const Circuit<Field>* circ, const PackedLayer& W0,
                        ProofAux<Field>* aux, bindings& bnd,
                        TranscriptSumcheck<Field>& ts, const Field& F,
                        size_t stride = 0) {
    const size_t nl = circ->nl;
    const corner_t nc = circ->nc;
    check(nl >= 1, "nl >= 1");
    check(nc >= 1, "nc >= 1");
    check(W0.n0() == nc, "input copies do not match the circuit");
    if (stride == 0) {
      stride = 1;
      while (stride * stride < nl) ++stride;
    }

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
    // Evaluates layers HI, HI - 1, ..., LO + 1 (HI's input must be in IN),
    // storing the inputs in[HI - 1], ..., in[LO]. With KEEP_ALL false, an
    // input is dropped once the next layer is evaluated, unless it is a
    // checkpoint (index % STRIDE == 0).
    auto evaluate = [&](size_t hi, size_t lo, bool keep_all) {
      for (size_t l = hi; l > lo; --l) {
        const corner_t nv = circ->l[l - 1].nw;
        auto out = std::make_unique<PackedLayer>(nc, nv, F);
        if (!eval_layer(circ->l[l].quad.get(), nv, input(l), out.get(), terms,
                        start, row, F)) {
          return false;
        }
        if (!keep_all && l + 1 < nl && l % stride != 0) in[l].reset();
        in[l - 1] = std::move(out);
      }
      return true;
    };
    // The first evaluation, then the outputs (layer 0), which must be zero.
    if (!evaluate(nl - 1, 0, /*keep_all=*/false)) return false;
    if (!eval_layer(circ->l[0].quad.get(), circ->nv, input(0), nullptr, terms,
                    start, row, F)) {
      return false;
    }

    // Sumcheck, with one buffer of the layer after its first two copy
    // rounds (a quarter of the copies; half for two copies), one of the EQ
    // sums of the pairs of copies and one of a wire scaled by them
    // (copy_rounds).
    Dense<Field> work(nc <= 2 ? (nc + 1) / 2 : (nc + 3) / 4, max_wires);
    std::vector<Elt> eqx((nc + 1) / 2), scaled((nc + 3) / 4);
    auto run = [&](size_t ly, Eqs<Field>* EQ, HQuad<Field>* EQUAD,
                   const Elt& alpha) {
      if (ly + 1 < nl && in[ly] == nullptr) {
        // The segment above the next checkpoint (or the inputs). It was
        // evaluated before, so it cannot fail now.
        const size_t hi = std::min(nl - 1, (ly / stride + 1) * stride);
        check(evaluate(hi, ly, /*keep_all=*/true), "segment evaluation");
      }
      // The claim of the layer: zero on the outputs, which are zero (checked
      // above), then W[R,C] + alpha W[L,C] of the layer before. The
      // assertions add beta times zero.
      const Elt claim =
          ly == 0 ? F.zero() : F.addf(bnd.wc[0], F.mulf(alpha, bnd.wc[1]));
      layer_packed(pr, pad, ts, bnd, ly, nc, circ->logc, circ->l[ly].logw, EQ,
                   EQUAD, input(ly), &work, eqx, scaled, claim, F);
      in[ly].reset();
    };
    prove_layers(pr, pad, circ, run, aux, bnd, ts, F);
    return true;
  }

  // The body of prove(). RUN(ly, EQ, EQUAD, alpha) proves layer LY (layer()
  // or layer_packed()); it is called for ly = 0, 1, ..., nl-1.
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

      run(ly, &EQ, EQUAD.get(), alpha);

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
  // of one is not multiplied. In characteristic two, an output wire whose
  // terms are all bit products with coefficient one (or assertions) is
  // computed by words. The work and the branches depend only on which wires
  // are bit wires (the circuit structure), not on the bit values.
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
    std::vector<uint64_t> acc(W.words());
    std::vector<typename Coords::Scalar> srow(Coords::kOn ? n0 : 0);
    for (corner_t g = 0; g < nv; ++g) {
      if constexpr (Field::kCharacteristicTwo) {
        // In characteristic two, a sum of products of bit wires with
        // coefficients one is their XOR, a bit wire: computed 64 copies per
        // word. Same values as eval_term.
        bool bits = true;
        for (size_t t = start[g]; t < start[g + 1]; ++t) {
          const ecorner& ec = terms[t];
          bits &= W.bits(corner_t(ec.h[0])) != nullptr &&
                  W.bits(corner_t(ec.h[1])) != nullptr &&
                  (ec.v == zero || ec.v == F.one());
        }
        if (bits) {
          std::fill(acc.begin(), acc.end(), 0);
          uint64_t fail = 0;
          for (size_t t = start[g]; t < start[g + 1]; ++t) {
            const ecorner& ec = terms[t];
            const uint64_t* a = W.bits(corner_t(ec.h[1]));
            const uint64_t* b = W.bits(corner_t(ec.h[0]));
            if (ec.v == zero) {  // an assertion
              for (size_t k = 0; k < acc.size(); ++k) fail |= a[k] & b[k];
            } else {
              for (size_t k = 0; k < acc.size(); ++k) acc[k] ^= a[k] & b[k];
            }
          }
          if (out == nullptr) {
            for (uint64_t x : acc) fail |= x;
          } else {
            out->set_bits(g, acc.data());
          }
          if (fail != 0) return false;
          continue;
        }
      }
      if constexpr (Coords::kOn && !Field::kCharacteristicTwo) {
        // Terms with base-field coefficients on bit or base-coordinate
        // wires (all of the ML-DSA circuits over Fq^12): the output is
        // computed in the base field. Same values as eval_term.
        bool base = true;
        for (size_t t = start[g]; t < start[g + 1]; ++t) {
          const ecorner& ec = terms[t];
          base &= F.in_subfield(ec.v) && W.in_base(corner_t(ec.h[0])) &&
                  W.in_base(corner_t(ec.h[1]));
        }
        if (base) {
          if (!eval_base(terms, start[g], start[g + 1], W, srow, F)) {
            return false;
          }
          if (out != nullptr) {
            out->set_base(g, srow.data());
          } else {
            for (corner_t c = 0; c < n0; ++c) {
              if (srow[c] != F.base_field().zero()) return false;
            }
          }
          continue;
        }
      }
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

  // The terms [T0, T1) of one output wire into S[0, n0), in the base field
  // (not upstream): every coefficient lies in the base field and every hand
  // is a bit or base-coordinate wire. False if an assertion fails.
  static bool eval_base(const std::vector<ecorner>& terms, size_t t0,
                        size_t t1, const PackedLayer& W,
                        std::vector<typename Coords::Scalar>& S,
                        const Field& F) {
    using Scalar = typename Coords::Scalar;
    const auto& B = F.base_field();
    const corner_t n0 = W.n0();
    const Scalar zero = B.zero(), one = B.one();
    const Scalar value[2] = {zero, one};
    std::fill(S.begin(), S.begin() + n0, zero);
    for (size_t t = t0; t < t1; ++t) {
      const ecorner& ec = terms[t];
      const Scalar v = ec.v.e[0];
      const bool assert0 = v == zero;
      const uint64_t* ba = W.bits(corner_t(ec.h[1]));
      const uint64_t* bb = W.bits(corner_t(ec.h[0]));
      const Scalar* sa = W.base(corner_t(ec.h[1]));
      const Scalar* sb = W.base(corner_t(ec.h[0]));
      bool nonzero = false;
      for (corner_t c = 0; c < n0; ++c) {
        const Scalar a =
            ba != nullptr ? value[(ba[c / 64] >> (c % 64)) & 1] : sa[c];
        const Scalar b =
            bb != nullptr ? value[(bb[c / 64] >> (c % 64)) & 1] : sb[c];
        const Scalar x = B.mulf(a, b);
        if (assert0) {
          nonzero |= x != zero;
        } else {
          B.add(S[c], B.mulf(v, x));
        }
      }
      if (nonzero) return false;
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
      const auto X = a != nullptr ? W.full(r) : W.full(l);
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
      const auto A = W.full(l);
      const auto B = W.full(r);
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
             Dense<Field>* W, const Field& F) {
    check(EQ->n() == W->n0_, "EQ->n() == W->n0_");

    check(logw <= Proof<Field>::kMaxBindings, "logw <= kMaxBindings");
    check(logc <= Proof<Field>::kMaxBindings, "logc <= kMaxBindings");

    // Bind the C variables to Q.
    // Note that binding C variables takes O(number_of_copies * circuit_size)
    // while binding R, L takes O(circuit_size * log(circuit_size)). In most
    // cases number_of_copies > log(circuit_size), so we don't have to
    // optimize binding R, L.
    for (size_t round = 0; round < logc; ++round) {
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

    hand_rounds(pr, pad, ts, bnd, layer, logw, EQ, EQUAD, W, F);
  }

  // The rounds of layer() after the copy rounds: bind r to R and l to L,
  // store the claims W[R,C] and W[L,C] in the proof and, without the pad,
  // in BND.wc (not upstream), and set BND to the new bindings. LAZY (the
  // packed prover) sums the round polynomials before their reduction.
  void hand_rounds(Proof<Field>* pr, const Proof<Field>* pad,
                   TranscriptSumcheck<Field>& ts, bindings& bnd, size_t layer,
                   size_t logw, Eqs<Field>* EQ, HQuad<Field>* EQUAD,
                   Dense<Field>* W, const Field& F, bool lazy = false) {
    bnd.logv = logw;
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
        if (lazy) {
          // At the points 0 and 2 (p(1) is implied), summed before the
          // reduction (not upstream; MacOf): the same polynomial.
          auto s0 = Mac::zero(F), s2 = Mac::zero(F);
          for (corner_t l = 0; l < QW.n0_; l += 2) {
            const FWPoly a =
                FWPoly::extend(WH[hand]->t2_at_corners(l, 0, F), F);
            const FWPoly b = FWPoly::extend(QW.t2_at_corners(l, 0, F), F);
            Mac::mac(s0, a[0], b[0], F);
            Mac::mac(s2, a[2], b[2], F);
          }
          sum.t_[0] = Mac::reduce(s0, F);
          sum.t_[2] = Mac::reduce(s2, F);
        } else {
          for (corner_t l = 0; l < QW.n0_; l += 2) {
            WPoly poly = wpoly_at_dense(WH[hand], l, 0, F)
                             .mul(wpoly_at_dense(&QW, l, 0, F), F);
            sum.add(poly, F);
          }
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
    bnd.wc[0] = WC[0];
    bnd.wc[1] = WC[1];
    end_layer(pr, pad, ts, layer, WC, F);
  }

  // A copy round with the EQ factored out (not upstream; Gruen, "Some
  // Improvements for the PIOP for ZeroCheck", ePrint 2024/108). At round k,
  // entry j of EQ covers the copies [j 2^k, (j + 1) 2^k); if they are all
  // below nc, the entry is a product over the bits of j, so a pair of
  // entries 2p, 2p + 1 that both cover full blocks ("pure") is
  // ((1 - q) E[p], q E[p]) with E[p] their sum and q = Q[k]. All pairs but
  // the last are pure. The pure pairs add up to eq(q, X) H(X) with
  //
  //   H(X) = sum_terms v sum_pure E[p] W[r](X) W[l](X)
  //
  // of degree 2. The round needs H(T), for the endpoint T of the round, and
  // the coefficient H2 of X^2; the other endpoint follows from the claim
  // s(0) + s(1) of the round. A last pair that is not pure adds
  // EQ_L(X) P(X), with P(X) = sum_terms v W[r](X) W[l](X) on that pair. The
  // polynomial is that of layer(). T alternates between rounds (so both
  // ways are used), unless its coefficient (1 - q or q) is zero.
  struct Round {
    corner_t n0, npairs, nfull;  // copies, pairs, pure pairs
    size_t t;
    Elt q, el0, el1;  // EQ of the last pair, if not pure, or zero
  };
  struct Sums {
    Elt ht, h2;      // H(T) and H2
    Elt p0, p1, p2;  // P(0), P(1) and the coefficient of X^2 of P
  };

  // The round ROUND on EQ, with Q = Q[ROUND], for NC copies; EQX[p] = E[p].
  static Round begin_round(const Dense<Field>& EQ, size_t round, corner_t nc,
                           const Elt& q, std::vector<Elt>& eqx,
                           const Field& F) {
    Round rd;
    rd.n0 = EQ.n0_;
    rd.npairs = (rd.n0 + 1) / 2;
    // The last pair is pure if it covers 2 npairs 2^k copies, all below nc.
    rd.nfull = (2 * rd.npairs) << round == nc ? rd.npairs : rd.npairs - 1;
    check(eqx.size() >= rd.nfull, "eqx too small");
    rd.q = q;
    rd.t = round % 2;
    const Elt c[2] = {F.subf(F.one(), q), q};
    if (c[1 - rd.t] == F.zero()) rd.t = 1 - rd.t;
    for (corner_t p = 0; p < rd.nfull; ++p) {
      eqx[p] = F.addf(EQ.v_[2 * p], EQ.v_[2 * p + 1]);
    }
    rd.el0 = EQ.at_corners(2 * rd.nfull, 0, F);
    rd.el1 = EQ.at_corners(2 * rd.nfull + 1, 0, F);
    return rd;
  }

  // P(0), P(1), P2 of the last pair, if not pure, for wires with the values
  // (A0, A1) and (B0, B1) there (zero past the last copy).
  static void last_pair(const Round& rd, const Elt& a0, const Elt& a1,
                        const Elt& b0, const Elt& b1, const Elt& v, Sums& s,
                        const Field& F) {
    if (rd.nfull == rd.npairs) return;
    const Elt p0 = F.mulf(v, F.mulf(a0, b0));
    F.add(s.p0, p0);
    if (2 * rd.nfull + 1 < rd.n0) {
      F.add(s.p1, F.mulf(v, F.mulf(a1, b1)));
      F.add(s.p2, F.mulf(v, F.mulf(F.subf(a1, a0), F.subf(b1, b0))));
    } else {
      F.add(s.p2, p0);  // A1 = B1 = 0
    }
  }

  // Ends the round: the polynomial s from the sums and CLAIM, sent as in
  // round_c(); CLAIM becomes s(R) for the challenge R, which is returned.
  Elt end_round(Proof<Field>* pr, const Proof<Field>* pad,
                TranscriptSumcheck<Field>& ts, size_t ly, size_t round,
                const Round& rd, const Sums& s, Elt& claim, const Field& F) {
    const Elt c[2] = {F.subf(F.one(), rd.q), rd.q};
    const Elt l0 = F.mulf(rd.el0, s.p0), l1 = F.mulf(rd.el1, s.p1);
    // c[0] H(0) + c[1] H(1) = claim - L(0) - L(1).
    Elt h[2];
    h[rd.t] = s.ht;
    h[1 - rd.t] =
        F.mulf(F.subf(F.subf(claim, F.addf(l0, l1)), F.mulf(c[rd.t], s.ht)),
               F.invertf(c[1 - rd.t]));
    const Elt h1 = F.subf(F.subf(h[1], h[0]), s.h2);  // coefficient of X
    const Elt p1 = F.subf(F.subf(s.p1, s.p0), s.p2);
    FCPoly full;
    for (size_t k = 0; k < 4; ++k) {
      const Elt x = F.poly_evaluation_point(k);
      const Elt hx = F.addf(h[0], F.mulf(x, F.addf(h1, F.mulf(x, s.h2))));
      const Elt px = F.addf(s.p0, F.mulf(x, F.addf(p1, F.mulf(x, s.p2))));
      const Elt eq = F.addf(c[0], F.mulf(x, F.subf(c[1], c[0])));
      const Elt el = F.addf(rd.el0, F.mulf(x, F.subf(rd.el1, rd.el0)));
      full[k] = F.addf(F.mulf(eq, hx), F.mulf(el, px));
    }
    CPoly sent(full);
    sent[1] = F.zero();  // as layer(): p(1) is implied
    const Elt rnd = round_c(pr, pad, ts, ly, round, sent, F);
    claim = full.eval_lagrange(rnd, F);
    return rnd;
  }

  // The copy rounds FIRST, ..., LOGC - 1 of layer() on the dense W, for NC
  // copies, with CLAIM the claim of round FIRST (Round). The terms come in
  // runs of one wire r (about two terms per run in the sponge circuits):
  // SCALED[c] = E[c / 2] W[r, c] is computed once per run, so a pure pair
  // takes two multiplications per term.
  void copy_rounds(Proof<Field>* pr, const Proof<Field>* pad,
                   TranscriptSumcheck<Field>& ts, bindings& bnd, size_t ly,
                   size_t first, corner_t nc, size_t logc, Eqs<Field>* EQ,
                   HQuad<Field>* EQUAD, Dense<Field>* W, std::vector<Elt>& eqx,
                   std::vector<Elt>& scaled, Elt claim, const Field& F) {
    for (size_t round = first; round < logc; ++round) {
      // BND.q[round] is still the copy binding of EQ: it is set below.
      const Round rd = begin_round(*EQ, round, nc, bnd.q[round], eqx, F);
      check(scaled.size() >= 2 * rd.nfull, "scaled buffer too small");
      const corner_t n0 = W->n0_;
      const Elt zero = F.zero();
      Sums s{zero, zero, zero, zero, zero};
      corner_t run = W->n1_;  // the wire in SCALED, none yet
      for (index_t i = 0; i < EQUAD->n_; ++i) {
        const corner_t r(EQUAD->hc_[i].h[0]);
        const Elt* a = &W->v_[n0 * r];
        const Elt* b = &W->v_[n0 * corner_t(EQUAD->hc_[i].h[1])];
        if (r != run) {
          run = r;
          for (corner_t c = 0; c < 2 * rd.nfull; ++c) {
            scaled[c] = F.mulf(eqx[c / 2], a[c]);
          }
        }
        auto ht = Mac::zero(F), h2 = Mac::zero(F);
        for (corner_t p = 0; p < rd.nfull; ++p) {
          const Elt* x = &scaled[2 * p];
          const Elt* y = b + 2 * p;
          Mac::mac(ht, x[rd.t], y[rd.t], F);
          Mac::mac(h2, F.subf(x[1], x[0]), F.subf(y[1], y[0]), F);
        }
        const Elt& v = EQUAD->vc_[i].v;
        F.add(s.ht, F.mulf(v, Mac::reduce(ht, F)));
        F.add(s.h2, F.mulf(v, Mac::reduce(h2, F)));
        const corner_t c = 2 * rd.nfull;
        if (c < n0) {
          last_pair(rd, a[c], c + 1 < n0 ? a[c + 1] : zero, b[c],
                    c + 1 < n0 ? b[c + 1] : zero, v, s, F);
        }
      }
      const Elt rnd = end_round(pr, pad, ts, ly, round, rd, s, claim, F);
      bnd.q[round] = rnd;
      EQ->bind(rnd, F);
      W->bind(rnd, F);
    }
  }

  // layer() for the packed input W of NC copies (not upstream), with CLAIM
  // the claim of the layer. The first two copy rounds read the packed wires
  // (the second by round1()), and their binding writes the layer, with a
  // quarter of the copies, into WORK (bind2(); with one copy round, its
  // binding with half the copies); the other copy rounds run on WORK
  // (copy_rounds). The copy rounds factor EQ out (Round); EQX holds the EQ
  // sums of the pure pairs, SCALED is a buffer of copy_rounds(). In the
  // first round, a pure pair adds E[p] W[r](T) W[l](T) and E[p] dW[r]
  // dW[l], dW the difference of the two copies. When both wires are bit
  // wires, these depend only on the four bits: the round adds E[p] into one
  // of 16 classes. Same polynomials and values as layer().
  void layer_packed(Proof<Field>* pr, const Proof<Field>* pad,
                    TranscriptSumcheck<Field>& ts, bindings& bnd, size_t ly,
                    corner_t nc, size_t logc, size_t logw, Eqs<Field>* EQ,
                    HQuad<Field>* EQUAD, const PackedLayer& W,
                    Dense<Field>* work, std::vector<Elt>& eqx,
                    std::vector<Elt>& scaled, Elt claim, const Field& F) {
    check(logw <= Proof<Field>::kMaxBindings, "logw <= kMaxBindings");
    check(logc <= Proof<Field>::kMaxBindings, "logc <= kMaxBindings");
    check(EQ->n() == W.n0(), "EQ->n() == W.n0()");
    check(work->v_.size() >= (logc >= 2 ? (W.n0() + 3) / 4
                                         : (W.n0() + 1) / 2) * W.n1(),
          "work buffer too small");
    if (logc == 0) {
      W.unpack(*work);
      hand_rounds(pr, pad, ts, bnd, ly, logw, EQ, EQUAD, work, F,
                  /*lazy=*/true);
      return;
    }
    const corner_t n0 = W.n0();
    const Round rd = begin_round(*EQ, 0, nc, bnd.q[0], eqx, F);
    const Elt zero = F.zero();
    const Elt value[2] = {zero, F.one()};
    // The values of wire I at copies C and C + 1 (zero past the last copy).
    auto pair = [&](corner_t i, corner_t c, Elt& x0, Elt& x1) {
      if (const uint64_t* b = W.bits(i)) {
        x0 = value[(b[c / 64] >> (c % 64)) & 1];
        x1 = value[(b[c / 64] >> (c % 64 + 1)) & 1];
      } else {
        const auto x = W.full(i);
        x0 = x[c];
        x1 = c + 1 < n0 ? x[c + 1] : zero;
      }
    };

    Sums s{zero, zero, zero, zero, zero};
    for (index_t i = 0; i < EQUAD->n_; ++i) {
      const corner_t r(EQUAD->hc_[i].h[0]);
      const corner_t l(EQUAD->hc_[i].h[1]);
      Elt ht = zero, h2 = zero;
      if (!bit_pairs(r, l, W, rd, eqx, ht, h2, F) &&
          !base_pairs(r, l, W, rd, eqx, ht, h2, F)) {
        full_pairs(r, l, W, rd, eqx, ht, h2, F);
      }
      const Elt& v = EQUAD->vc_[i].v;
      F.add(s.ht, F.mulf(v, ht));
      F.add(s.h2, F.mulf(v, h2));
      const corner_t c = 2 * rd.nfull;
      if (c < n0) {
        Elt a0, a1, b0, b1;
        pair(r, c, a0, a1);
        pair(l, c, b0, b1);
        last_pair(rd, a0, a1, b0, b1, v, s, F);
      }
    }
    const Elt rnd = end_round(pr, pad, ts, ly, 0, rd, s, claim, F);
    bnd.q[0] = rnd;
    EQ->bind(rnd, F);

    if (logc >= 2) {
      // The second round from the packed input too; WORK holds the layer
      // bound by both rounds.
      round1(pr, pad, ts, bnd, ly, nc, EQ, EQUAD, W, rnd, eqx, claim, F);
      bind2(W, rnd, bnd.q[1], work, F);
      copy_rounds(pr, pad, ts, bnd, ly, 2, nc, logc, EQ, EQUAD, work, eqx,
                  scaled, claim, F);
      hand_rounds(pr, pad, ts, bnd, ly, logw, EQ, EQUAD, work, F,
                  /*lazy=*/true);
      return;
    }

    // One copy round: bind it, WORK[w, p] = W[w, 2p] + rnd (W[w, 2p + 1]
    // - W[w, 2p]), with W[w, n0] = 0.
    const corner_t npairs = rd.npairs;
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
      } else if (bind_base(rnd, W, i, x, F)) {
      } else {
        const auto f = W.full(i);
        for (corner_t p = 0; p < npairs; ++p) {
          const corner_t c = 2 * p;
          x[p] = c + 1 < n0 ? affine_interpolation(rnd, f[c], f[c + 1], F)
                            : affine_interpolation_nz_z(rnd, f[c], F);
        }
      }
    }
    hand_rounds(pr, pad, ts, bnd, ly, logw, EQ, EQUAD, work, F,
                  /*lazy=*/true);
  }

  // The second copy round of layer_packed() (not upstream), from the packed
  // input W and the first challenge R0. After the first round, entry e of
  // a wire is v(e) = a + R0 d with a = W[2e] and d = W[2e + 1] - W[2e] (W
  // is zero past the last copy). For a pure pair of entries (2p, 2p + 1),
  // the products v_r(T) v_l(T) and dv_r dv_l, dv = v(2p + 1) - v(2p), are
  // c0 + R0 c1 + R0^2 c2, with c0, c1, c2 products of a and d: bits for bit
  // wires in characteristic two (round1_bits), base elements for bit and
  // base wires in odd characteristic (round1_base). Other wires take the
  // entries as elements (round1_full). CLAIM is the claim of the round.
  void round1(Proof<Field>* pr, const Proof<Field>* pad,
              TranscriptSumcheck<Field>& ts, bindings& bnd, size_t ly,
              corner_t nc, Eqs<Field>* EQ, HQuad<Field>* EQUAD,
              const PackedLayer& W, const Elt& r0, std::vector<Elt>& eqx,
              Elt& claim, const Field& F) {
    // BND.q[1] is still the copy binding of EQ.
    const Round rd = begin_round(*EQ, 1, nc, bnd.q[1], eqx, F);
    const corner_t n0 = W.n0();
    const Elt zero = F.zero();
    const Elt value[2] = {zero, F.one()};
    const Elt r0sq = F.mulf(r0, r0);
    // Entry E of wire I as an element (zero past the last entry).
    auto entry = [&](corner_t i, corner_t e) {
      const uint64_t* b = W.bits(i);
      auto at = [&](corner_t c) {
        if (c >= n0) return zero;
        if (b != nullptr) return value[(b[c / 64] >> (c % 64)) & 1];
        return W.full(i)[c];
      };
      const Elt x = at(2 * e);
      return F.addf(x, F.mulf(r0, F.subf(at(2 * e + 1), x)));
    };
    Sums s{zero, zero, zero, zero, zero};
    for (index_t i = 0; i < EQUAD->n_; ++i) {
      const corner_t r(EQUAD->hc_[i].h[0]);
      const corner_t l(EQUAD->hc_[i].h[1]);
      // H[0]: the coefficients of sum E[p] v_r(T) v_l(T), H[1] of sum E[p]
      // dv_r dv_l.
      Elt h[2][3] = {{zero, zero, zero}, {zero, zero, zero}};
      if (!round1_bits(r, l, W, rd, eqx, h, F) &&
          !round1_base(r, l, W, rd, eqx, h, F)) {
        round1_full(r, l, rd, eqx, entry, h, F);
      }
      const Elt& v = EQUAD->vc_[i].v;
      for (size_t k = 0; k < 2; ++k) {
        const Elt hk = F.addf(h[k][0], F.addf(F.mulf(r0, h[k][1]),
                                             F.mulf(r0sq, h[k][2])));
        F.add(k == 0 ? s.ht : s.h2, F.mulf(v, hk));
      }
      const corner_t c = 2 * rd.nfull;
      if (c < rd.n0) {
        last_pair(rd, entry(r, c), entry(r, c + 1), entry(l, c),
                  entry(l, c + 1), v, s, F);
      }
    }
    const Elt rnd = end_round(pr, pad, ts, ly, 1, rd, s, claim, F);
    bnd.q[1] = rnd;
    EQ->bind(rnd, F);
  }

  // round1() for bit wires R and L in characteristic two: the coefficients
  // are bits (AND for products, XOR for sums), computed for the 16 pairs of
  // a word at once; E[p] adds into one of 64 classes of the six bits, and
  // H[k][j] is the sum of the classes with bit 3 k + j. False (nothing
  // done) otherwise.
  static bool round1_bits(corner_t r, corner_t l, const PackedLayer& W,
                          const Round& rd, const std::vector<Elt>& eqx,
                          Elt h[2][3], const Field& F) {
    if constexpr (!Field::kCharacteristicTwo) {
      return false;
    } else {
      const uint64_t* br = W.bits(r);
      const uint64_t* bl = W.bits(l);
      if (br == nullptr || bl == nullptr) return false;
      // Bit 4q of a plane is the value at pair q of a word (copies 4q to
      // 4q + 3, bits b0 to b3): A = a(2p + T), D = d(2p + T), and the
      // differences DA = a(2p + 1) - a(2p), DD = d(2p + 1) - d(2p).
      constexpr uint64_t kM = 0x1111111111111111u;
      struct Planes {
        uint64_t a, d, da, dd;
      };
      auto planes = [&](uint64_t x) {
        const uint64_t b0 = x & kM, b1 = (x >> 1) & kM, b2 = (x >> 2) & kM,
                       b3 = (x >> 3) & kM;
        return Planes{rd.t == 0 ? b0 : b2, rd.t == 0 ? b0 ^ b1 : b2 ^ b3,
                      b0 ^ b2, b0 ^ b1 ^ b2 ^ b3};
      };
      Elt cls[64];
      for (Elt& x : cls) x = F.zero();
      for (corner_t p0 = 0; p0 < rd.nfull; p0 += 16) {
        const Planes x = planes(br[p0 / 16]), y = planes(bl[p0 / 16]);
        const uint64_t c0 = x.a & y.a, c1 = (x.a & y.d) ^ (x.d & y.a),
                       c2 = x.d & y.d;
        const uint64_t g0 = x.da & y.da, g1 = (x.da & y.dd) ^ (x.dd & y.da),
                       g2 = x.dd & y.dd;
        const uint64_t lo = c0 | c1 << 1 | c2 << 2 | g0 << 3;
        const uint64_t hi = g1 | g2 << 1;
        const corner_t np = std::min<corner_t>(16, rd.nfull - p0);
        for (corner_t q = 0; q < np; ++q) {
          const size_t k = ((lo >> (4 * q)) & 15) | (((hi >> (4 * q)) & 3) << 4);
          F.add(cls[k], eqx[p0 + q]);
        }
      }
      for (size_t k = 0; k < 64; ++k) {
        for (size_t j = 0; j < 6; ++j) {
          if ((k >> j) & 1) F.add(h[j / 3][j % 3], cls[k]);
        }
      }
      return true;
    }
  }

  // round1() for bit or base-coordinate wires R and L in odd
  // characteristic: the coefficients are products in the base field, and
  // E[p] times them is summed before its reduction (MacOf). False (nothing
  // done) otherwise.
  static bool round1_base(corner_t r, corner_t l, const PackedLayer& W,
                          const Round& rd, const std::vector<Elt>& eqx,
                          Elt h[2][3], const Field& F) {
    if constexpr (!Coords::kOn || Field::kCharacteristicTwo) {
      return false;
    } else {
      using Scalar = typename Coords::Scalar;
      const auto& B = F.base_field();
      if (!W.in_base(r) || !W.in_base(l)) return false;
      const uint64_t* br = W.bits(r);
      const uint64_t* bl = W.bits(l);
      const Scalar* sr = W.base(r);
      const Scalar* sl = W.base(l);
      const Scalar value[2] = {B.zero(), B.one()};
      // a, d at entry 2p + T, and the differences da, dd.
      struct Coef {
        Scalar a, d, da, dd;
      };
      auto coef = [&](const uint64_t* b, const Scalar* s, corner_t c) {
        Scalar w[4];
        for (size_t k = 0; k < 4; ++k) {
          w[k] = b != nullptr ? value[(b[(c + k) / 64] >> ((c + k) % 64)) & 1]
                              : s[c + k];
        }
        const Scalar d0 = B.subf(w[1], w[0]), d1 = B.subf(w[3], w[2]);
        return Coef{rd.t == 0 ? w[0] : w[2], rd.t == 0 ? d0 : d1,
                    B.subf(w[2], w[0]), B.subf(d1, d0)};
      };
      const auto z = Mac::zero(F);
      typename Mac::Acc a[2][3] = {{z, z, z}, {z, z, z}};
      for (corner_t p = 0; p < rd.nfull; ++p) {
        const Coef x = coef(br, sr, 4 * p), y = coef(bl, sl, 4 * p);
        Mac::mac(a[0][0], eqx[p], B.mulf(x.a, y.a), F);
        Mac::mac(a[0][1], eqx[p], B.addf(B.mulf(x.a, y.d), B.mulf(x.d, y.a)),
                 F);
        Mac::mac(a[0][2], eqx[p], B.mulf(x.d, y.d), F);
        Mac::mac(a[1][0], eqx[p], B.mulf(x.da, y.da), F);
        Mac::mac(a[1][1], eqx[p],
                 B.addf(B.mulf(x.da, y.dd), B.mulf(x.dd, y.da)), F);
        Mac::mac(a[1][2], eqx[p], B.mulf(x.dd, y.dd), F);
      }
      for (size_t k = 0; k < 2; ++k) {
        for (size_t j = 0; j < 3; ++j) h[k][j] = Mac::reduce(a[k][j], F);
      }
      return true;
    }
  }

  // round1() for any wires R and L, with the entries as elements (ENTRY):
  // H[0][0] and H[1][0] are the sums, the other coefficients zero.
  template <class Entry>
  static void round1_full(corner_t r, corner_t l, const Round& rd,
                          const std::vector<Elt>& eqx, const Entry& entry,
                          Elt h[2][3], const Field& F) {
    auto st = Mac::zero(F), s2 = Mac::zero(F);
    for (corner_t p = 0; p < rd.nfull; ++p) {
      const Elt x0 = entry(r, 2 * p), x1 = entry(r, 2 * p + 1);
      const Elt y0 = entry(l, 2 * p), y1 = entry(l, 2 * p + 1);
      Mac::mac(st, eqx[p], F.mulf(rd.t == 0 ? x0 : x1, rd.t == 0 ? y0 : y1),
               F);
      Mac::mac(s2, eqx[p], F.mulf(F.subf(x1, x0), F.subf(y1, y0)), F);
    }
    h[0][0] = Mac::reduce(st, F);
    h[1][0] = Mac::reduce(s2, F);
  }

  // Binds the first two copy variables of W into WORK (not upstream):
  // WORK[w, k] = sum_i L_i W[w, 4k + i], with L = ((1 - R0)(1 - R1),
  // R0 (1 - R1), (1 - R0) R1, R0 R1) and W zero past the last copy: the
  // values of two binds. A bit wire reads a table of the 16 values of its
  // four bits.
  static void bind2(const PackedLayer& W, const Elt& r0, const Elt& r1,
                    Dense<Field>* work, const Field& F) {
    const corner_t n0 = W.n0(), nq = (n0 + 3) / 4;
    check(work->v_.size() >= nq * W.n1(), "work buffer too small");
    work->n0_ = nq;
    work->n1_ = W.n1();
    const Elt one = F.one();
    const Elt s0 = F.subf(one, r0), s1 = F.subf(one, r1);
    const Elt L[4] = {F.mulf(s0, s1), F.mulf(r0, s1), F.mulf(s0, r1),
                      F.mulf(r0, r1)};
    Elt table[16];
    for (size_t k = 0; k < 16; ++k) {
      table[k] = F.zero();
      for (size_t i = 0; i < 4; ++i) {
        if ((k >> i) & 1) F.add(table[k], L[i]);
      }
    }
    for (corner_t i = 0; i < W.n1(); ++i) {
      Elt* x = &work->v_[nq * i];
      if (const uint64_t* b = W.bits(i)) {
        for (corner_t k = 0; k < nq; ++k) {
          const corner_t c = 4 * k;
          x[k] = table[(b[c / 64] >> (c % 64)) & 15];
        }
        continue;
      }
      if constexpr (Coords::kOn && !Field::kCharacteristicTwo) {
        if (const auto* sb = W.base(i)) {
          for (corner_t k = 0; k < nq; ++k) {
            auto a = Mac::zero(F);
            for (size_t j = 0; j < 4 && 4 * k + j < n0; ++j) {
              Mac::mac(a, L[j], sb[4 * k + j], F);
            }
            x[k] = Mac::reduce(a, F);
          }
          continue;
        }
      }
      const auto f = W.full(i);
      for (corner_t k = 0; k < nq; ++k) {
        x[k] = F.zero();
        for (size_t j = 0; j < 4 && 4 * k + j < n0; ++j) {
          F.add(x[k], F.mulf(L[j], f[4 * k + j]));
        }
      }
    }
  }

  // The binding of layer_packed() for wire I of W kept by base coordinates
  // S, in a field of odd characteristic (not upstream): X[p] = S[2p] + R
  // (S[2p + 1] - S[2p]), with S[n0] = 0, by products of R and base
  // elements. False (nothing done) otherwise.
  static bool bind_base(const Elt& R, const PackedLayer& W, corner_t i,
                        Elt* x, const Field& F) {
    if constexpr (!Coords::kOn || Field::kCharacteristicTwo) {
      return false;
    } else {
      const auto* s = W.base(i);
      if (s == nullptr) return false;
      const auto& B = F.base_field();
      const corner_t n0 = W.n0();
      for (corner_t c = 0; c < n0; c += 2) {
        if (c + 1 < n0) {
          x[c / 2] = F.mulf(R, B.subf(s[c + 1], s[c]));
          F.add(x[c / 2], F.of_scalar(s[c]));
        } else {
          x[c / 2] = F.subf(F.of_scalar(s[c]), F.mulf(R, s[c]));
        }
      }
      return true;
    }
  }

  // The pure pairs of the first round (layer_packed) for bit wires R and L:
  // HT += sum_p E[p] W[r](T) W[l](T) and H2 += sum_p E[p] dW[r] dW[l], by
  // the 16 classes of the four bits. False (nothing done) if a wire is not
  // a bit wire.
  static bool bit_pairs(corner_t r, corner_t l, const PackedLayer& W,
                        const Round& rd, const std::vector<Elt>& eqx, Elt& ht,
                        Elt& h2, const Field& F) {
    const uint64_t* br = W.bits(r);
    const uint64_t* bl = W.bits(l);
    if (br == nullptr || bl == nullptr) return false;
    Elt cls[16];
    for (Elt& x : cls) x = F.zero();
    for (corner_t p = 0; p < rd.nfull; ++p) {
      const corner_t c = 2 * p;  // c and c + 1 are in one word
      const size_t k = ((br[c / 64] >> (c % 64)) & 3) |
                       (((bl[c / 64] >> (c % 64)) & 3) << 2);
      F.add(cls[k], eqx[p]);
    }
    // k = r0 | r1 << 1 | l0 << 2 | l1 << 3.
    for (size_t k = 0; k < 16; ++k) {
      if (((k >> rd.t) & (k >> (2 + rd.t)) & 1) != 0) F.add(ht, cls[k]);
      const int d = (int((k >> 1) & 1) - int(k & 1)) *
                    (int((k >> 3) & 1) - int((k >> 2) & 1));
      if (d == 1) F.add(h2, cls[k]);
      if (d == -1) F.sub(h2, cls[k]);
    }
    return true;
  }

  // bit_pairs() when both wires are bits or kept by base coordinates (not
  // upstream): the products W[r] W[l] in the base field (Fq for Fq^12), and
  // E[p] times a base element (K base multiplications instead of K^2).
  // False (nothing done) if the field has no base coordinates or a wire is
  // outside its base field.
  static bool base_pairs(corner_t r, corner_t l, const PackedLayer& W,
                         const Round& rd, const std::vector<Elt>& eqx,
                         Elt& ht, Elt& h2, const Field& F) {
    using Coords = BaseCoordinates<Field>;
    if constexpr (!Coords::kOn || Field::kCharacteristicTwo) {
      return false;
    } else {
      using Scalar = typename Coords::Scalar;
      const auto& B = F.base_field();
      const uint64_t* br = W.bits(r);
      const uint64_t* bl = W.bits(l);
      const Scalar* sr = W.base(r);
      const Scalar* sl = W.base(l);
      if ((br == nullptr && sr == nullptr) || (bl == nullptr && sl == nullptr)) {
        return false;
      }
      const Scalar value[2] = {B.zero(), B.one()};
      auto at = [&](const uint64_t* b, const Scalar* s, corner_t c) {
        return b != nullptr ? value[(b[c / 64] >> (c % 64)) & 1] : s[c];
      };
      auto st = Mac::zero(F), s2 = Mac::zero(F);
      for (corner_t p = 0; p < rd.nfull; ++p) {
        const corner_t c = 2 * p;
        const Scalar r0 = at(br, sr, c), r1 = at(br, sr, c + 1);
        const Scalar l0 = at(bl, sl, c), l1 = at(bl, sl, c + 1);
        const Scalar pt = B.mulf(rd.t == 0 ? r0 : r1, rd.t == 0 ? l0 : l1);
        const Scalar p2 = B.mulf(B.subf(r1, r0), B.subf(l1, l0));
        Mac::mac(st, eqx[p], pt, F);
        Mac::mac(s2, eqx[p], p2, F);
      }
      F.add(ht, Mac::reduce(st, F));
      F.add(h2, Mac::reduce(s2, F));
      return true;
    }
  }

  // The pure pairs of the first round for any wires R and L. A bit wire
  // selects the other factor, without a multiplication.
  static void full_pairs(corner_t r, corner_t l, const PackedLayer& W,
                         const Round& rd, const std::vector<Elt>& eqx,
                         Elt& ht, Elt& h2, const Field& F) {
    const uint64_t* br = W.bits(r);
    const uint64_t* bl = W.bits(l);
    if (br != nullptr || bl != nullptr) {
      // One bit wire B and one full wire X: B(T) X(T) and dB dX, with dB in
      // {-1, 0, 1}.
      const uint64_t* b = br != nullptr ? br : bl;
      const auto x = br != nullptr ? W.full(l) : W.full(r);
      auto st = Mac::zero(F), s2 = Mac::zero(F);
      for (corner_t p = 0; p < rd.nfull; ++p) {
        const corner_t c = 2 * p;
        const size_t b0 = (b[c / 64] >> (c % 64)) & 1;
        const size_t b1 = (b[c / 64] >> (c % 64 + 1)) & 1;
        const Elt x0 = x[c], x1 = x[c + 1];
        const Elt dx = F.subf(x1, x0);
        const Elt pick[2] = {F.zero(), rd.t == 0 ? x0 : x1};
        const Elt diff[3] = {F.negf(dx), F.zero(), dx};
        Mac::mac(st, eqx[p], pick[rd.t == 0 ? b0 : b1], F);
        Mac::mac(s2, eqx[p], diff[1 + b1 - b0], F);
      }
      F.add(ht, Mac::reduce(st, F));
      F.add(h2, Mac::reduce(s2, F));
      return;
    }
    const auto a = W.full(r);
    const auto b = W.full(l);
    auto st = Mac::zero(F), s2 = Mac::zero(F);
    for (corner_t p = 0; p < rd.nfull; ++p) {
      const corner_t c = 2 * p;
      const Elt a0 = a[c], a1 = a[c + 1], b0 = b[c], b1 = b[c + 1];
      Mac::mac(st, eqx[p], F.mulf(rd.t == 0 ? a0 : a1, rd.t == 0 ? b0 : b1),
               F);
      Mac::mac(s2, eqx[p], F.mulf(F.subf(a1, a0), F.subf(b1, b0)), F);
    }
    F.add(ht, Mac::reduce(st, F));
    F.add(h2, Mac::reduce(s2, F));
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
