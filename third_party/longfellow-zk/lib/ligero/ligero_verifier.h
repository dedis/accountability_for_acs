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

#ifndef PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_VERIFIER_H_
#define PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_VERIFIER_H_

#include <stddef.h>

#include <array>
#include <type_traits>
#include <utility>
#include <vector>

#include "algebra/blas.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_transcript.h"
#include "merkle/merkle_commitment.h"
#include "random/transcript.h"
#include "util/crypto.h"

namespace proofs {
// The code I evaluates at chosen outputs alone (interpolate_at; not
// upstream).
template <class I, class Field, class = void>
struct InterpolatesAt : std::false_type {};
template <class I, class Field>
struct InterpolatesAt<
    I, Field,
    std::void_t<decltype(std::declval<const I&>().interpolate_at(
        nullptr, size_t(0), nullptr, nullptr, std::declval<const Field&>()))>>
    : std::true_type {};

template <class Field, class InterpolatorFactory>
class LigeroVerifier {
  using Elt = typename Field::Elt;

 public:
  static void receive_commitment(const LigeroCommitment<Field>& commitment,
                                 Transcript& ts) {
    // P -> V
    LigeroTranscript<Field>::write_commitment(commitment, ts);
  }

  static bool verify(const char** why, const LigeroParam<Field>& p,
                     const LigeroCommitment<Field>& commitment,
                     const LigeroProof<Field>& proof, Transcript& ts, size_t nl,
                     size_t nllterm,
                     const LigeroLinearConstraint<Field> llterm[/*nllterm*/],
                     const LigeroHash& hash_of_llterm, const Elt b[/*nl*/],
                     const LigeroQuadraticConstraint lqc[/*nq*/],
                     const InterpolatorFactory& interpolator, const Field& F,
                     const LigeroProductRow<Field>* row = nullptr,
                     size_t nrowp = 1) {
    const LigeroTermSpan<Field> span{llterm, nllterm, 0};
    LigeroUnitSpan<Field> none;
    none.row_offset = nl;
    return verify(why, p, commitment, proof, ts, nl, &span, 1, none,
                  hash_of_llterm, b, lqc, interpolator, F, row, nrowp);
  }

  // Not upstream: the linear terms as SPANS and UNITS, and the linear-test
  // vector one row at a time (LigeroRows). B holds the right-hand sides of
  // rows [0, UNITS.row_offset), UNITS.b those of the rows after.
  static bool verify(const char** why, const LigeroParam<Field>& p,
                     const LigeroCommitment<Field>& commitment,
                     const LigeroProof<Field>& proof, Transcript& ts, size_t nl,
                     const LigeroTermSpan<Field> spans[], size_t nspans,
                     const LigeroUnitSpan<Field>& units,
                     const LigeroHash& hash_of_llterm, const Elt b[],
                     const LigeroQuadraticConstraint lqc[/*nq*/],
                     const InterpolatorFactory& interpolator, const Field& F,
                     const LigeroProductRow<Field>* row, size_t nrowp) {
    if (why == nullptr) {
      return false;
    }

    // Replay the protocol first in order to compute all the
    // challenges.  In particular, we need IDX before we can do
    // anything useful.
    const Challenges ch(p, proof, ts, nl, hash_of_llterm, F);
    const std::vector<Elt>& u_ldt = ch.u_ldt;
    const std::vector<Elt>& alphal = ch.alphal;
    const std::vector<std::array<Elt, 3>>& alphaq = ch.alphaq;
    const std::vector<Elt>& u_quad = ch.u_quad;
    const std::vector<size_t>& idx = ch.idx;

    if (!subfield_check(p, proof, F)) {
      *why = "subfield_check failed";
      return false;
    }

    if (!merkle_check(p, commitment, proof, &idx[0], F)) {
      *why = "merkle_check failed";
      return false;
    }

    if (!low_degree_check(p, proof, &idx[0], &u_ldt[0], interpolator, F)) {
      *why = "low_degree_check failed";
      return false;
    }

    {
      // linear check
      const LigeroRows<Field> rows(p, nl, spans, nspans, units, &alphal[0],
                                   lqc, &alphaq[0], F, row, nrowp);
      if (!dot_check(p, proof, &idx[0], rows, interpolator, F)) {
        *why = "dot_check failed";
        return false;
      }

      // check the putative value of the inner product
      check(units.row_offset <= nl, "unit rows");
      Elt want_dot = Blas<Field>::dot(units.row_offset, b, 1, &alphal[0], 1, F);
      if (units.row_offset < nl) {
        F.add(want_dot, Blas<Field>::dot(nl - units.row_offset, units.b, 1,
                                         &alphal[units.row_offset], 1, F));
      }
      Elt proof_dot = Blas<Field>::dot1(p.w, &proof.y_dot[p.r], 1, F);
      if (want_dot != proof_dot) {
        *why = "wrong dot product";
        return false;
      }
    }

    if (!quadratic_check(p, proof, &idx[0], &u_quad[0], interpolator, F)) {
      *why = "quadratic_check failed";
      return false;
    }

    *why = "ok";
    return true;
  }

  // Not upstream: replays TS as verify() does and checks only the Merkle
  // openings, so that a caller can reject a proof with a bad commitment or
  // opening before it builds the linear constraints. TS is consumed; pass a
  // copy.
  static bool check_openings(const LigeroParam<Field>& p,
                             const LigeroCommitment<Field>& commitment,
                             const LigeroProof<Field>& proof, Transcript& ts,
                             size_t nl, const LigeroHash& hash_of_llterm,
                             const Field& F) {
    const Challenges ch(p, proof, ts, nl, hash_of_llterm, F);
    return subfield_check(p, proof, F) &&
           merkle_check(p, commitment, proof, &ch.idx[0], F);
  }

 private:
  using Interpolator =
      typename std::remove_reference<decltype(*std::declval<
          const InterpolatorFactory&>().make(0, 0))>::type;

  // The verifier challenges, in transcript order.
  struct Challenges {
    std::vector<Elt> u_ldt;
    std::vector<Elt> alphal;
    std::vector<std::array<Elt, 3>> alphaq;
    std::vector<Elt> u_quad;
    std::vector<size_t> idx;

    Challenges(const LigeroParam<Field>& p, const LigeroProof<Field>& proof,
               Transcript& ts, size_t nl, const LigeroHash& hash_of_llterm,
               const Field& F)
        : u_ldt(p.nwqrow),
          alphal(nl),
          alphaq(p.nq),
          u_quad(p.nqtriples),
          idx(p.nreq) {
      // P -> V
      ts.write(hash_of_llterm.bytes, hash_of_llterm.kLength);

      // V -> P
      LigeroTranscript<Field>::gen_uldt(&u_ldt[0], p, ts, F);

      // V -> P
      LigeroTranscript<Field>::gen_alphal(nl, &alphal[0], ts, F);
      LigeroTranscript<Field>::gen_alphaq(&alphaq[0], p, ts, F);

      // V -> P
      LigeroTranscript<Field>::gen_uquad(&u_quad[0], p, ts, F);

      // P -> V
      ts.write(&proof.y_ldt[0], 1, p.block, F);
      ts.write(&proof.y_dot[0], 1, p.dblock, F);
      ts.write(&proof.y_quad_0[0], 1, p.r, F);
      ts.write(&proof.y_quad_2[0], 1, p.dblock - p.block, F);

      // V -> P
      LigeroTranscript<Field>::gen_idx(&idx[0], p, ts, F);
    }
  };

  static void interpolate_req_columns(Elt yp[/*nreq*/],
                                      const LigeroParam<Field>& p, size_t ylen,
                                      const Elt y[/*ylen*/],
                                      const size_t idx[/*nreq*/],
                                      const InterpolatorFactory& interpolator,
                                      const Field& F) {
    const auto interpy = interpolator.make(ylen, p.block_enc);
    std::vector<Elt> yext(p.block_enc);
    Blas<Field>::copy(ylen, &yext[0], 1, y, 1);
    interpy->interpolate(&yext[0]);
    Blas<Field>::gather(p.nreq, &yp[0], &yext[p.dblock], idx);
  }

  // The opened elements of the rows hashed by subfield bytes lie in the
  // subfield (LigeroParam::nsub; not upstream).
  static bool subfield_check(const LigeroParam<Field>& p,
                             const LigeroProof<Field>& proof, const Field& F) {
    for (size_t i = p.iw; i < p.iw + p.nsub; ++i) {
      for (size_t j = 0; j < p.nreq; ++j) {
        if (!F.in_subfield(proof.req_at(i, j))) return false;
      }
    }
    return true;
  }

  static bool merkle_check(const LigeroParam<Field>& p,
                           const LigeroCommitment<Field>& commitment,
                           const LigeroProof<Field>& proof,
                           const size_t idx[/*nreq*/], const Field& F) {
    auto updhash = [&](size_t r, Hash& sha) {
      LigeroCommon<Field>::column_hash(p, &proof.req_at(0, r), p.nreq, sha, F);
    };

    return MerkleCommitmentVerifier::verify(p.block_enc - p.dblock,
                                            commitment.root, proof.merkle, idx,
                                            p.nreq, updhash);
  }

  static bool low_degree_check(const LigeroParam<Field>& p,
                               const LigeroProof<Field>& proof,
                               const size_t idx[/*nreq*/],
                               const Elt u_ldt[/*nrow*/],
                               const InterpolatorFactory& interpolator,
                               const Field& F) {
    std::vector<Elt> yc(p.nreq);

    // the ILDT blinding row with coefficient 1
    Blas<Field>::copy(p.nreq, &yc[0], 1, &proof.req_at(p.ildt, 0), 1);

    // all remaining rows with coefficient u_ldt[]
    for (size_t i = 0; i < p.nwqrow; ++i) {
      Blas<Field>::axpy(p.nreq, &yc[0], 1, u_ldt[i], &proof.req_at(i + p.iw, 0),
                        1, F);
    }

    std::vector<Elt> yp(p.nreq);
    interpolate_req_columns(&yp[0], p, p.block, &proof.y_ldt[0], idx,
                            interpolator, F);

    if (!Blas<Field>::equal(p.nreq, &yp[0], 1, &yc[0], 1, F)) {
      return false;
    }

    return true;
  }

  static bool dot_check(const LigeroParam<Field>& p,
                        const LigeroProof<Field>& proof,
                        const size_t idx[/*nreq*/],
                        const LigeroRows<Field>& rows,
                        const InterpolatorFactory& interpolator,
                        const Field& F) {
    std::vector<Elt> yc(p.nreq);

    // the IDOT blinding row with coefficient 1
    Blas<Field>::copy(p.nreq, &yc[0], 1, &proof.req_at(p.idot, 0), 1);

    {
      const auto interpA = interpolator.make(p.block, p.block_enc);

      std::vector<Elt> Aext(p.block_enc);
      std::vector<Elt> Areq(p.nreq);
      // The opened columns, if the code evaluates there alone (not
      // upstream; ComponentwiseReedSolomon::interpolate_at).
      std::vector<size_t> pos(p.nreq);
      for (size_t j = 0; j < p.nreq; ++j) pos[j] = p.dblock + idx[j];

      for (size_t i = 0; i < p.nwqrow; ++i) {
        LigeroCommon<Field>::layout_row(&Aext[0], p, i, rows, F);
        if constexpr (InterpolatesAt<Interpolator, Field>::value) {
          interpA->interpolate_at(&Aext[0], p.nreq, &pos[0], &Areq[0], F);
        } else {
          interpA->interpolate(&Aext[0]);
          Blas<Field>::gather(p.nreq, &Areq[0], &Aext[p.dblock], idx);
        }

        // Accumulate z += A[j] \otimes W[j].
        Blas<Field>::vaxpy(p.nreq, &yc[0], 1, &Areq[0], 1,
                           &proof.req_at(i + p.iw, 0), 1, F);
      }
    }

    std::vector<Elt> yp(p.nreq);
    interpolate_req_columns(&yp[0], p, p.dblock, &proof.y_dot[0], idx,
                            interpolator, F);

    if (!Blas<Field>::equal(p.nreq, &yp[0], 1, &yc[0], 1, F)) {
      return false;
    }
    return true;
  }

  static bool quadratic_check(const LigeroParam<Field>& p,
                              const LigeroProof<Field>& proof,
                              const size_t idx[/*nreq*/],
                              const Elt u_quad[/*nqtriples*/],
                              const InterpolatorFactory& interpolator,
                              const Field& F) {
    std::vector<Elt> yc(p.nreq);

    // the IQUAD blinding row with coefficient 1
    Blas<Field>::copy(p.nreq, &yc[0], 1, &proof.req_at(p.iquad, 0), 1);

    {
      std::vector<Elt> tmp(p.nreq);
      size_t iqx = p.iq;
      size_t iqy = iqx + p.nqtriples;
      size_t iqz = iqy + p.nqtriples;

      // all quadratic triples with coefficient u_ldt[]
      for (size_t i = 0; i < p.nqtriples; ++i) {
        // yc += u_quad[i] * (z[i] - x[i] * y[i])

        // tmp = z[i]
        Blas<Field>::copy(p.nreq, &tmp[0], 1, &proof.req_at(iqz + i, 0), 1);

        // tmp -= x[i] \otimes y[i]
        Blas<Field>::vymax(p.nreq, &tmp[0], 1, &proof.req_at(iqx + i, 0), 1,
                           &proof.req_at(iqy + i, 0), 1, F);

        // yc += u_quad[i] * tmp
        Blas<Field>::axpy(p.nreq, &yc[0], 1, u_quad[i], &tmp[0], 1, F);
      }
    }

    // reconstruct y_quad from the two parts in the proof
    std::vector<Elt> yquad(p.dblock);
    Blas<Field>::copy(p.r, &yquad[0], 1, &proof.y_quad_0[0], 1);
    Blas<Field>::clear(p.w, &yquad[p.r], 1, F);
    Blas<Field>::copy(p.dblock - p.block, &yquad[p.block], 1,
                      &proof.y_quad_2[0], 1);

    // interpolate y_quad at the opened columns
    std::vector<Elt> yp(p.nreq);
    interpolate_req_columns(&yp[0], p, p.dblock, &yquad[0], idx, interpolator,
                            F);

    if (!Blas<Field>::equal(p.nreq, &yp[0], 1, &yc[0], 1, F)) {
      return false;
    }
    return true;
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_VERIFIER_H_
