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

#ifndef PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_PROVER_H_
#define PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_PROVER_H_

#include <stddef.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include "algebra/blas.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_transcript.h"
#include "merkle/merkle_commitment.h"
#include "random/random.h"
#include "random/transcript.h"
#include "util/crypto.h"
#include "util/panic.h"

namespace proofs {
// Not upstream: the prover does not keep the encoded tableau. It keeps each
// witness row's input (its R random elements and W witnesses, the witnesses
// packed as bits when they are all 0 or 1) and encodes the row again when it
// needs it: at commit time, to hash the columns row by row; for the dot
// proof; and for the opened columns. The blinding and quadratic rows are
// kept encoded. The randomness is drawn in the upstream order, so the proof
// is the same.
template <class Field, class InterpolatorFactory>
class LigeroProver {
  using Elt = typename Field::Elt;

 public:
  explicit LigeroProver(const LigeroParam<Field> &p)
      : p_(p),
        mc_(p.block_enc - p.dblock),
        special_((p.iw + p.nrow - p.iq) * p.block_enc),
        wrand_(p.nwrow * p.r),
        words_((p.w + 63) / 64),
        full_index_(p.nwrow, kBits),
        wbits_(p.nwrow * words_, 0) {}

  // The SUBFIELD_BOUNDARY parameter is kind of a hack.
  //
  // Most, but not all, witnesses in W[] are known statically to be in
  // the subfield of Field, for example because they are bits or
  // bit-plucked values in the subfield.  For zero-knowledge, for
  // these witnesses, it suffices to choose blinding randomness in the
  // subfield, which yields a shorter proof since most column openings
  // are fully in the subfield.  The problem is now to distinguish
  // subfield witnesses from field witnesses.
  //
  // In the fullness of time we should have a compiler with typing
  // information (field vs subfield) of all input wires.  For now
  // we implement the following hack: W[i] is in the subfield for
  // i < SUBFIELD_BOUNDARY, and in the full field otherwise.
  // If you don't know better, set SUBFIELD_BOUNDARY = 0 which
  // trivially works for any input.
  //
  // Not upstream: W is any type whose W[j] gives witness j (an array, or a
  // view such as ZkProver's packed inputs); it is read only during commit.
  template <class Witness>
  void commit(LigeroCommitment<Field> &commitment, Transcript &ts,
              const Witness &W, const size_t subfield_boundary,
              const LigeroQuadraticConstraint lqc[/*nq*/],
              const InterpolatorFactory &interpolator, RandomEngine &rng,
              const Field &F) {
    // Paranoid check on the SUBFIELD_BOUNDARY correctness condition
    for (size_t i = 0; i < subfield_boundary; ++i) {
      check(F.in_subfield(W[i]), "element not in subfield");
    }

    layout(W, subfield_boundary, lqc, interpolator, rng, F);

    // Merkle commitment. Leaf j hashes the nonce and column j of the
    // extension (rows in order); one hash per column, fed row by row.
    const size_t ncol = p_.block_enc - p_.dblock;
    const std::vector<MerkleNonce> &nonce = mc_.draw_nonces(rng);
    std::vector<Hash> column(ncol);
    for (size_t j = 0; j < ncol; ++j) {
      column[j].Update(nonce[j].bytes, MerkleNonce::kLength);
    }
    const auto interp = interpolator.make(p_.block, p_.block_enc);
    std::vector<Elt> buf(p_.block_enc);
    for (size_t i = 0; i < p_.nrow; ++i) {
      const Elt *row = row_at(i, &buf[0], *interp);
      for (size_t j = 0; j < ncol; ++j) {
        uint8_t bytes[Field::kBytes];
        F.to_bytes_field(bytes, row[p_.dblock + j]);
        column[j].Update(bytes, sizeof(bytes));
      }
    }
    std::vector<Digest> leaves(ncol);
    for (size_t j = 0; j < ncol; ++j) column[j].DigestData(leaves[j].data);
    commitment.root = mc_.commit_leaves(leaves);

    // P -> V
    LigeroTranscript<Field>::write_commitment(commitment, ts);
  }

  // HASH_OF_LLTERM is a hash of LLTERM provided by the caller.  We
  // could compute the hash locally, but usually LLTERM has a special
  // structure that makes the computation faster on the caller's side.
  void prove(LigeroProof<Field> &proof, Transcript &ts, size_t nl,
             size_t nllterm,
             const LigeroLinearConstraint<Field> llterm[/*nllterm*/],
             const LigeroHash &hash_of_llterm,
             const LigeroQuadraticConstraint lqc[/*nq*/],
             const InterpolatorFactory &interpolator, const Field &F,
             const LigeroProductRow<Field> *row = nullptr) {
    {
      // P -> V
      // theorem statement
      ts.write(hash_of_llterm.bytes, hash_of_llterm.kLength);
    }

    {
      std::vector<Elt> u_ldt(p_.nwqrow);

      // V -> P
      LigeroTranscript<Field>::gen_uldt(&u_ldt[0], p_, ts, F);
      low_degree_proof(&proof.y_ldt[0], &u_ldt[0], F);
    }

    {
      std::vector<Elt> alphal(nl);
      std::vector<std::array<Elt, 3>> alphaq(p_.nq);
      std::vector<Elt> A(p_.nwqrow * p_.w);

      // V -> P
      LigeroTranscript<Field>::gen_alphal(nl, &alphal[0], ts, F);
      LigeroTranscript<Field>::gen_alphaq(&alphaq[0], p_, ts, F);

      LigeroCommon<Field>::inner_product_vector(&A[0], p_, nl, nllterm, llterm,
                                                &alphal[0], lqc, &alphaq[0], F,
                                                row);

      dot_proof(&proof.y_dot[0], &A[0], interpolator, F);
    }

    {
      std::vector<Elt> u_quad(p_.nqtriples);

      // V -> P
      LigeroTranscript<Field>::gen_uquad(&u_quad[0], p_, ts, F);
      quadratic_proof(&proof.y_quad_0[0], &proof.y_quad_2[0], &u_quad[0], F);
    }

    {
      // P -> V
      ts.write(&proof.y_ldt[0], 1, p_.block, F);
      ts.write(&proof.y_dot[0], 1, p_.dblock, F);
      ts.write(&proof.y_quad_0[0], 1, p_.r, F);
      ts.write(&proof.y_quad_2[0], 1, p_.dblock - p_.block, F);
    }

    {
      std::vector<size_t> idx(p_.nreq);
      // V -> P
      LigeroTranscript<Field>::gen_idx(&idx[0], p_, ts, F);

      compute_req(proof, &idx[0], interpolator);

      mc_.open(proof.merkle, &idx[0], p_.nreq);
    }
  }

 private:
  using Interpolator =
      typename std::remove_reference<decltype(*std::declval<
          const InterpolatorFactory &>().make(0, 0))>::type;

  bool is_witness_row(size_t i) const { return i >= p_.iw && i < p_.iq; }

  // An encoded blinding or quadratic row (i not a witness row).
  Elt *special_row(size_t i) {
    const size_t k = i < p_.iw ? i : p_.iw + (i - p_.iq);
    return &special_[k * p_.block_enc];
  }

  Elt &tableau_at(size_t i, size_t j) { return special_row(i)[j]; }

  // The input [RANDOM[R], WITNESS[W]] of witness row I into OUT[0, BLOCK).
  void witness_input(size_t i, Elt out[/*block*/], const Field &F) const {
    std::copy(&wrand_[i * p_.r], &wrand_[i * p_.r] + p_.r, out);
    if (full_index_[i] == kBits) {
      const uint64_t *b = &wbits_[i * words_];
      const Elt value[2] = {F.zero(), F.one()};
      for (size_t j = 0; j < p_.w; ++j) {
        out[p_.r + j] = value[(b[j / 64] >> (j % 64)) & 1];
      }
    } else {
      const Elt *x = &wfull_[full_index_[i] * p_.w];
      std::copy(x, x + p_.w, out + p_.r);
    }
  }

  // Row I of the tableau: kept for the blinding and quadratic rows, encoded
  // into BUF with INTERP (from BLOCK to its size) for a witness row.
  const Elt *row_at(size_t i, Elt *buf, const Interpolator &interp) {
    if (!is_witness_row(i)) return special_row(i);
    witness_input(i - p_.iw, buf, *field_);
    interp.interpolate(buf);
    return buf;
  }

  // fill t_[i, [0,n)] with random elements
  // If the base_only flag is true, then the random element is chosen from
  // the base field if F is a field extension.
  void random_row(Elt *row, size_t n, RandomEngine &rng, const Field &F) {
    for (size_t j = 0; j < n; ++j) {
      row[j] = rng.elt(F);
    }
  }

  void random_subfield_row(Elt *row, size_t n, RandomEngine &rng,
                           const Field &F) {
    for (size_t j = 0; j < n; ++j) {
      row[j] = rng.subfield_elt(F);
    }
  }

  // generate the ILDT and IDOT blinding rows
  void layout_blinding_rows(const InterpolatorFactory &interpolator,
                            RandomEngine &rng, const Field &F) {
    {
      // blinds of size [BLOCK]
      const auto interp = interpolator.make(p_.block, p_.block_enc);

      // low-degree blinding row
      random_row(special_row(p_.ildt), p_.block, rng, F);
      interp->interpolate(special_row(p_.ildt));
    }

    {
      // blinds of size [DBLOCK]
      const auto interp = interpolator.make(p_.dblock, p_.block_enc);

      // dot-product blinding row constrained to SUM(W) = 0. First
      // randomize the dblock:
      random_row(special_row(p_.idot), p_.dblock, rng, F);

      // Then constrain to sum(W) = 0
      Elt sum = Blas<Field>::dot1(p_.w, &tableau_at(p_.idot, p_.r), 1, F);
      F.sub(tableau_at(p_.idot, p_.r), sum);

      interp->interpolate(special_row(p_.idot));

      // quadratic-test blinding row constrained to W = 0.  First
      // randomize the entire dblock:
      random_row(special_row(p_.iquad), p_.dblock, rng, F);

      // Then constrain to W = 0
      Blas<Field>::clear(p_.w, &tableau_at(p_.iquad, p_.r), 1, F);

      interp->interpolate(special_row(p_.iquad));
    }
  }

  // The input of each witness row: random elements, and the witnesses,
  // packed as bits when they are all 0 or 1. The bits of row I are at word
  // I * words_; a row kept in full leaves them zero. The full rows are
  // counted first, so that wfull_ is allocated once. Packing does not
  // branch on the bit values. Every commit starts from a clear state.
  template <class Witness>
  void layout_witness_rows(const Witness &W, size_t subfield_boundary,
                           RandomEngine &rng, const Field &F) {
    std::fill(wbits_.begin(), wbits_.end(), 0);
    std::fill(full_index_.begin(), full_index_.end(), kBits);
    size_t nfull = 0;
    for (size_t i = 0; i < p_.nwrow; ++i) {
      // The WITNESS columns are zero after the witnesses that exist.
      const size_t max_col = std::min(p_.w, p_.nw - i * p_.w);
      uint64_t *b = &wbits_[i * words_];
      bool is_bits = true;
      for (size_t j = 0; j < max_col; ++j) {
        const Elt x = W[i * p_.w + j];
        const bool is_one = x == F.one();
        b[j / 64] |= uint64_t(is_one) << (j % 64);
        is_bits &= is_one | (x == F.zero());
      }
      if (!is_bits) {
        std::fill(b, b + words_, 0);
        full_index_[i] = nfull++;
      }
    }
    wfull_.resize(nfull * p_.w);

    for (size_t i = 0; i < p_.nwrow; ++i) {
      // TRUE if the entire row is in the subfield
      bool subfield_only = ((i + 1) * p_.w <= subfield_boundary);

      if (subfield_only) {
        random_subfield_row(&wrand_[i * p_.r], p_.r, rng, F);
      } else {
        random_row(&wrand_[i * p_.r], p_.r, rng, F);
      }

      if (full_index_[i] != kBits) {
        Elt *out = &wfull_[full_index_[i] * p_.w];
        Blas<Field>::clear(p_.w, out, 1, F);
        size_t max_col = std::min(p_.w, p_.nw - i * p_.w);
        for (size_t j = 0; j < max_col; ++j) out[j] = W[i * p_.w + j];
      }
    }
  }

  template <class Witness>
  void layout_quadratic_rows(const Witness &W,
                             const LigeroQuadraticConstraint lqc[/*nq*/],
                             const InterpolatorFactory &interpolator,
                             RandomEngine &rng, const Field &F) {
    const auto interp = interpolator.make(p_.block, p_.block_enc);

    // copy the multiplicand witnesses into the quadratic rows
    size_t iqx = p_.iq;
    size_t iqy = iqx + p_.nqtriples;
    size_t iqz = iqy + p_.nqtriples;

    for (size_t i = 0; i < p_.nqtriples; ++i) {
      random_row(special_row(iqx + i), p_.r, rng, F);
      random_row(special_row(iqy + i), p_.r, rng, F);
      random_row(special_row(iqz + i), p_.r, rng, F);

      // clear everything first, then overwrite the witnesses that
      // actually exist
      Blas<Field>::clear(p_.w, &tableau_at(iqx + i, p_.r), 1, F);
      Blas<Field>::clear(p_.w, &tableau_at(iqy + i, p_.r), 1, F);
      Blas<Field>::clear(p_.w, &tableau_at(iqz + i, p_.r), 1, F);

      for (size_t j = 0; j < p_.w && j + i * p_.w < p_.nq; ++j) {
        const auto *l = &lqc[j + i * p_.w];
        check(W[l->z] == F.mulf(W[l->x], W[l->y]),
              "invalid quadratic constraints");
        tableau_at(iqx + i, j + p_.r) = W[l->x];
        tableau_at(iqy + i, j + p_.r) = W[l->y];
        tableau_at(iqz + i, j + p_.r) = W[l->z];
      }
      interp->interpolate(special_row(iqx + i));
      interp->interpolate(special_row(iqy + i));
      interp->interpolate(special_row(iqz + i));
    }
  }

  template <class Witness>
  void layout(const Witness &W, size_t subfield_boundary,
              const LigeroQuadraticConstraint lqc[/*nq*/],
              const InterpolatorFactory &interpolator, RandomEngine &rng,
              const Field &F) {
    field_ = &F;
    layout_blinding_rows(interpolator, rng, F);
    layout_witness_rows(W, subfield_boundary, rng, F);
    layout_quadratic_rows(W, lqc, interpolator, rng, F);
  }

  void low_degree_proof(Elt y[/*block*/], const Elt u_ldt[/*nwqrow*/],
                        const Field &F) {
    // ILDT blinding row with coefficient 1
    Blas<Field>::copy(p_.block, y, 1, special_row(p_.ildt), 1);

    // all witness and quadratic rows with coefficient u_ldt[]; the first
    // BLOCK elements of a witness row are its input.
    std::vector<Elt> input(p_.block);
    for (size_t i = 0; i < p_.nwqrow; ++i) {
      const Elt *row = &input[0];
      if (is_witness_row(i + p_.iw)) {
        witness_input(i, &input[0], F);
      } else {
        row = special_row(i + p_.iw);
      }
      Blas<Field>::axpy(p_.block, y, 1, u_ldt[i], row, 1, F);
    }
  }

  void dot_proof(Elt y[/*dblock*/], const Elt A[/*nwqrow, w*/],
                 const InterpolatorFactory &interpolator, const Field &F) {
    const auto interpA = interpolator.make(p_.block, p_.dblock);

    // IDOT blinding row with coefficient 1
    Blas<Field>::copy(p_.dblock, y, 1, special_row(p_.idot), 1);

    std::vector<Elt> Aext(p_.dblock);
    std::vector<Elt> buf(p_.dblock);
    for (size_t i = 0; i < p_.nwqrow; ++i) {
      LigeroCommon<Field>::layout_Aext(&Aext[0], p_, i, &A[0], F);
      interpA->interpolate(&Aext[0]);

      // Accumulate y += A \otimes W, with the witness row encoded to DBLOCK.
      const Elt *row = row_at(i + p_.iw, &buf[0], *interpA);
      Blas<Field>::vaxpy(p_.dblock, &y[0], 1, &Aext[0], 1, row, 1, F);
    }
  }

  void quadratic_proof(Elt y0[/*r*/], Elt y2[/*dblock - block*/],
                       const Elt u_quad[/*nqtriples*/], const Field &F) {
    std::vector<Elt> y(p_.dblock);
    std::vector<Elt> tmp(p_.dblock);

    // IQUAD blinding row with coefficient 1
    Blas<Field>::copy(p_.dblock, &y[0], 1, special_row(p_.iquad), 1);

    size_t iqx = p_.iq;
    size_t iqy = iqx + p_.nqtriples;
    size_t iqz = iqy + p_.nqtriples;

    for (size_t i = 0; i < p_.nqtriples; ++i) {
      // y += u_quad[i] * (z[i] - x[i] * y[i])

      // tmp = z[i]
      Blas<Field>::copy(p_.dblock, &tmp[0], 1, special_row(iqz + i), 1);

      // tmp -= x[i] \otimes y[i]
      Blas<Field>::vymax(p_.dblock, &tmp[0], 1, special_row(iqx + i), 1,
                         special_row(iqy + i), 1, F);

      // y += u_quad[i] * tmp
      Blas<Field>::axpy(p_.dblock, &y[0], 1, u_quad[i], &tmp[0], 1, F);
    }

    // sanity check: the W part of Y is zero
    bool ok = Blas<Field>::equal0(p_.w, &y[p_.r], 1, F);
    check(ok, "W part is nonzero");

    // extract the first and last parts
    Blas<Field>::copy(p_.r, y0, 1, &y[0], 1);
    Blas<Field>::copy(p_.dblock - p_.block, y2, 1, &y[p_.block], 1);
  }

  void compute_req(LigeroProof<Field> &proof, const size_t idx[/*nreq*/],
                   const InterpolatorFactory &interpolator) {
    const auto interp = interpolator.make(p_.block, p_.block_enc);
    std::vector<Elt> buf(p_.block_enc);
    for (size_t i = 0; i < p_.nrow; ++i) {
      const Elt *row = row_at(i, &buf[0], *interp);
      Blas<Field>::gather(p_.nreq, &proof.req_at(i, 0), row + p_.dblock, idx);
    }
  }

  static constexpr size_t kBits = ~size_t(0);

  const LigeroParam<Field> p_; /* safer to make copy */
  MerkleCommitment mc_;
  const Field *field_ = nullptr;  // set by layout(); outlives the prover
  // The encoded blinding rows, then the encoded quadratic rows.
  std::vector<Elt> special_ /*[iw + nrow - iq, block_enc]*/;
  std::vector<Elt> wrand_ /*[nwrow, r]*/;
  size_t words_; /* 64-bit words per row */
  std::vector<size_t> full_index_; /*[nwrow] kBits, or the full row index */
  std::vector<uint64_t> wbits_ /*[nwrow, words_]*/;
  std::vector<Elt> wfull_ /*[full rows, w]*/;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_LIGERO_LIGERO_PROVER_H_
