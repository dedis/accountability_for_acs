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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_REF_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_REF_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/sha3/sha3_reference.h"

// ----------------------------------------------------------------------------
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!
//
// This ML-DSA circuit is an experimental implementation for research purposes.
// It has not been fully vetted and is not recommended for production use cases
// at this time.
//
// ML-DSA is specified in
//
//      FIPS 204
//      Federal Information Processing Standards Publication
//      Module-Lattice-Based Digital
//      Signature Standard
//      https://csrc.nist.gov/pubs/fips/204/final
//
// ----------------------------------------------------------------------------

namespace proofs {
namespace ml_dsa {

// Defined as SHAKE256(str, 8 * len) bits
template <size_t N>
void H(const std::vector<uint8_t>& in, std::array<uint8_t, N>& out) {
  Sha3Reference::shake256Hash(in.data(), in.size(), out.data(), out.size());
}

// Defined as SHAKE128(str, 8 * len) bits
void G(const std::vector<uint8_t>& in, size_t len, std::vector<uint8_t>& out);

Rq mulf(Rq a, const Rq& b);
Rq addf(Rq a, const Rq& b);
Rq subf(Rq a, const Rq& b);
Rq scalef(Rq a, const Elt& s);

// Inplace versions of
// Algorithm 41 NTT(omega)
// Algorithm 42 NTT−1(omega)̂
void Ntt(Rq& a);
void InvNtt(Rq& a);

// Algorithm 30 RejNTTPoly(rho)
// Samples a polynomial in T_q.
Rq RejNTTPoly(const std::vector<uint8_t>& rho, size_t num_blocks);

// Algorithm 29 SampleInBall(rho)
// Samples a polynomial c in R with coefficients from {-1, 0, 1} and Hamming
// weight tau.
template <typename Params>
Rq SampleInBall(const std::array<uint8_t, Params::c_tilde_bytes>& rho);

// Algorithm 32 ExpandA(rho)
// Samples a K x L matrix A_hat of elements of T_q.
// Input: A seed rho (32 bytes).
// Output: Matrix A_hat in (T_q)^(K x L).
template <typename Params>
typename MLDsaTypes<Params>::MatrixA ExpandA(const std::vector<uint8_t>& rho);

// Algorithm 36 Decompose(r)
// Decomposes r into (r1, r0) such that r = r1*(2*gamma2) + r0 mod q
template <typename Params>
std::pair<int32_t, int32_t> Decompose(int32_t r);

// Algorithm 40 UseHint(h, r)
// Returns the high bits of r adjusted according to hint h.
// Input: Boolean h, r in Z_q.
// Output: r1 in Z with 0 <= r1 <= (q-1)/(2*gamma2).
template <typename Params>
uint32_t UseHint(bool h, int32_t r);

// Algorithm 19 BitUnpack(v, a, b)
// Reverses the procedure BitPack. For ML-DSA, used for unpacking z with b =
// gamma1
std::optional<Rq> BitUnpack(const std::vector<uint8_t>& v, uint32_t a,
                            uint32_t b);

// Algorithm 21 HintBitUnpack(y)
// Reverses the procedure HintBitPack.
template <typename Params>
std::optional<std::array<std::array<bool, N>, Params::K>> HintBitUnpack(
    const std::vector<uint8_t>& y);

// Algorithm 27 sigDecode(sigma)
// Reverses the procedure sigEncode.
template <typename Params>
std::optional<typename MLDsaTypes<Params>::Signature> sigDecode(
    const std::vector<uint8_t>& sigma);

// Algorithm 18 SimpleBitUnpack(v, b)
// Extracts coefficients from a byte array.
Rq SimpleBitUnpack(const std::vector<uint8_t>& v, uint32_t b);

// Algorithm 23 pkDecode(pk)
// Reverses the procedure pkEncode, expanding rho to a_hat and unpacking t1.
template <typename Params>
typename MLDsaTypes<Params>::PublicKey pkDecode(const std::vector<uint8_t>& pk);

// Algorithm 18 SimpleBitPack(w, b)
// Packs coefficients into a byte array.
std::vector<uint8_t> SimpleBitPack(const Rq& w, uint32_t b);

// Algorithm 28 w1Encode(w1)
// Encodes a polynomial vector w1 into a byte string.
// Input: w1 in R_q^k with coefficients in [0, (q-1)/(2*gamma2) - 1].
// Output: A byte string representation w1_tilde.
template <typename Params>
std::array<uint8_t, Params::K * Params::w1_bytes> w1Encode(
    const typename MLDsaTypes<Params>::RqK& w1);

// Preprocesses the message by binding the context to it:
// M' = 0x00 || |ctx| || ctx || msg
std::optional<std::vector<uint8_t>> preprocess_message(
    const std::vector<uint8_t>& msg, const std::vector<uint8_t>& ctx);

}  // namespace ml_dsa
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_REF_H_
