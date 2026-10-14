// LigeroProver keeps each witness row's input and encodes rows on demand
// (not upstream). It must produce the proof of the upstream prover, which
// keeps the whole encoded tableau (ReferenceLigeroProver), byte for byte, and
// the proof must verify. The prover under test first commits to another
// witness (rows of the other kind), as a reused upstream prover can.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp.h"
#include "algebra/reed_solomon.h"
#include "circuits/tests/pq/slh_dsa/reference_ligero_prover.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "ligero/ligero_param.h"
#include "ligero/ligero_prover.h"
#include "ligero/ligero_verifier.h"
#include "random/transcript.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

struct GF2Setup {
  using Field = GF2_128<>;
  using RSFactory = LCH14ReedSolomonFactory<Field>;
  Field F;
  RSFactory rsf;
  GF2Setup() : F(), rsf(F) {}
};

struct FpSetup {
  using Field = Fp<1>;
  using Conv = FFTConvolutionFactory<Field>;
  using RSFactory = ReedSolomonFactory<Field, Conv>;
  Field F;
  Conv conv;
  RSFactory rsf;
  FpSetup()
      : F("18446744069414584321"),
        conv(F, F.of_scalar(1753635133440165772ull), 1ull << 32),
        rsf(conv, F) {}
};

// Witness kinds: every element 0/1 (as the SLH-DSA proofs), the first half
// 0/1 and the rest random, all random, and 0/1 with one random element in
// every 1000.
enum Kind { kBits, kHalf, kRandom, kSparse };

template <class S>
void ExpectSameProof(const S& s, Kind kind, size_t nw, size_t nq) {
  using Field = typename S::Field;
  using Elt = typename Field::Elt;
  using Llc = LigeroLinearConstraint<Field>;
  const Field& F = s.F;
  Transcript gen((uint8_t*)"witness", 7);

  // Witness, with nq quadratic triples at the end: W[z] = W[x] * W[y].
  std::vector<Elt> W(nw);
  size_t subfield_boundary = 0;
  for (size_t i = 0; i < nw; ++i) {
    bool bit = kind == kBits || (kind == kHalf && i < nw / 2) ||
               (kind == kSparse && i % 1000 != 999);
    uint8_t b;
    gen.bytes(&b, 1);
    W[i] = bit ? (b & 1 ? F.one() : F.zero()) : gen.elt(F);
    if (bit && subfield_boundary == i) subfield_boundary = i + 1;
  }
  std::vector<LigeroQuadraticConstraint> lqc(nq);
  for (size_t k = 0; k < nq; ++k) {
    lqc[k] = {k, k + 1, nw - 1 - k};
    W[nw - 1 - k] = F.mulf(W[k], W[k + 1]);
  }
  subfield_boundary = std::min(subfield_boundary, nw - nq);
  for (size_t i = 0; i < subfield_boundary; ++i) {
    if (!F.in_subfield(W[i])) subfield_boundary = i;
  }

  // Linear constraints A W = b with random coefficients, and one product
  // row (LigeroProductRow; not upstream) given to the reference prover as
  // terms.
  const size_t nl = 6;
  std::vector<Llc> a;
  std::vector<Elt> rhs(nl, F.zero());
  for (size_t c = 0; c + 1 < nl; ++c) {
    for (size_t t = 0; t < 40; ++t) {
      uint8_t idx[4];
      gen.bytes(idx, 4);
      const size_t w = (idx[0] | idx[1] << 8 | idx[2] << 16) % nw;
      const Elt k = gen.elt(F);
      a.push_back(Llc{c, w, k});
      F.add(rhs[c], F.mulf(k, W[w]));
    }
  }
  LigeroProductRow<Field> row{nl - 1, 3, std::vector<Elt>(7),
                              std::vector<Elt>(50)};
  for (auto& x : row.u) x = gen.elt(F);
  for (auto& x : row.v) x = gen.elt(F);
  std::vector<Llc> expanded = a;
  for (size_t i = 0; i < row.u.size(); ++i) {
    for (size_t j = 0; j < row.v.size(); ++j) {
      const size_t w = row.first + i * row.v.size() + j;
      const Elt k = F.mulf(row.u[i], row.v[j]);
      expanded.push_back(Llc{row.c, w, k});
      F.add(rhs[row.c], F.mulf(k, W[w]));
    }
  }
  const LigeroHash hash{0x12, 0x34};

  const LigeroParam<Field> param(nw, nq, 4, 32);
  ASSERT_GT(param.nwrow, 2u);

  // The two provers with the same randomness and transcript.
  ReferenceLigeroProver<Field, typename S::RSFactory> ref(param);
  LigeroProver<Field, typename S::RSFactory> lp(param);
  {
    std::vector<Elt> other(nw);
    for (size_t i = 0; i < nw; ++i) {
      other[i] = kind == kRandom ? F.zero() : gen.elt(F);
    }
    for (size_t k = 0; k < nq; ++k) {
      other[nw - 1 - k] = F.mulf(other[k], other[k + 1]);
    }
    Transcript rng((uint8_t*)"other", 5), t((uint8_t*)"other", 5);
    LigeroCommitment<Field> com;
    lp.commit(com, t, &other[0], 0, &lqc[0], s.rsf, rng, F);
  }
  Transcript rng_ref((uint8_t*)"rng", 3), rng_lp((uint8_t*)"rng", 3);
  Transcript t_ref((uint8_t*)"t", 1), t_lp((uint8_t*)"t", 1);
  LigeroCommitment<Field> com_ref, com_lp;
  ref.commit(com_ref, t_ref, &W[0], subfield_boundary, &lqc[0], s.rsf, rng_ref,
             F);
  lp.commit(com_lp, t_lp, &W[0], subfield_boundary, &lqc[0], s.rsf, rng_lp, F);
  EXPECT_EQ(std::memcmp(com_ref.root.data, com_lp.root.data,
                        sizeof(com_ref.root.data)),
            0);

  LigeroProof<Field> want(&param), got(&param);
  ref.prove(want, t_ref, nl, expanded.size(), &expanded[0], hash, &lqc[0],
            s.rsf, F);
  lp.prove(got, t_lp, nl, a.size(), &a[0], hash, &lqc[0], s.rsf, F, &row);
  EXPECT_EQ(got.y_ldt, want.y_ldt);
  EXPECT_EQ(got.y_dot, want.y_dot);
  EXPECT_EQ(got.y_quad_0, want.y_quad_0);
  EXPECT_EQ(got.y_quad_2, want.y_quad_2);
  EXPECT_EQ(got.req, want.req);
  ASSERT_EQ(got.merkle.path.size(), want.merkle.path.size());
  for (size_t i = 0; i < got.merkle.path.size(); ++i) {
    EXPECT_EQ(std::memcmp(got.merkle.path[i].data, want.merkle.path[i].data,
                          sizeof(got.merkle.path[i].data)),
              0);
  }
  for (size_t i = 0; i < param.nreq; ++i) {
    EXPECT_EQ(std::memcmp(got.merkle.nonce[i].bytes,
                          want.merkle.nonce[i].bytes, MerkleNonce::kLength),
              0);
  }

  Transcript tv((uint8_t*)"t", 1);
  LigeroVerifier<Field, typename S::RSFactory>::receive_commitment(com_lp, tv);
  const char* why = "";
  EXPECT_TRUE((LigeroVerifier<Field, typename S::RSFactory>::verify(
      &why, param, com_lp, got, tv, nl, a.size(), &a[0], hash, &rhs[0],
      &lqc[0], s.rsf, F, &row)))
      << why;
}

TEST(LigeroProver, SameProofAsUpstreamGF2) {
  const GF2Setup s;
  for (Kind kind : {kBits, kHalf, kRandom, kSparse}) {
    ExpectSameProof(s, kind, 20000, 3);
  }
}

TEST(LigeroProver, SameProofAsUpstreamFp) {
  const FpSetup s;
  for (Kind kind : {kBits, kHalf, kRandom, kSparse}) {
    ExpectSameProof(s, kind, 20000, 3);
  }
}

}  // namespace
}  // namespace proofs
