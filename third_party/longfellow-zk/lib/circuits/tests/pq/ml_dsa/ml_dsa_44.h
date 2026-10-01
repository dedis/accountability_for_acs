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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_H_

#include "circuits/tests/pq/ml_dsa/ml_dsa_circuit.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"

namespace proofs {

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
// A public key in the system is a pair (rho, t1).
//
// The value rho is used to derive the pk matrix A \in R_q^{k x l}.
// The matrix T = A.s_1 + s_2 in R_q^k, and t1 is a rounded version of T.
// The hint h \in R_2^k.
//
// These operations are performed outside of the circuit and
// used as inputs for the Verifier.
// rho, t1 = _unpack_pk(pk)
// A_hat = _expand_matrix_from_seed(rho)
// tr = _h(pk, 64)    # 64-byte hash of the public key
// t1 = t1.scale(1 << self.d)
// t1 = t1.to_ntt()
// 1.  (rho, t1) = pkDecode(pk)
// Decode public key bytes.
// rho: 32-byte seed for generating matrix A.
// t1: Vector of 4 polynomials in R_q (k=4).
//     Represents the high bits of A*s + t.

// 2.  (c_tilde, z, h) = sigDecode(sigma)  [ALWAYS PRIVATE]
// Decode signature bytes.
// c_tilde: 32-byte hash commitment (the "challenge" seed).
// z: Vector of 4 polynomials in R_q (l=4). The masked secret vector.
// h: Vector of 4 polynomials in R_q (k=4). The hint vector used to
//    recover high bits.
// 3.  IF h is INVALID (e.g., decoding failed or malformed) THEN
//         RETURN False
//     END IF

// 4.  A_hat = ExpandA(rho)
// Expand the public matrix A from the seed rho.
// A_hat: 4x4 Matrix of polynomials in R_q (k=4, l=4).
// Note: The matrix is generated and stored directly in NTT (Number
// Theoretic Transform) representation.
// ----------------------------------------------------------------------------

template <class LogicCircuit, class Field>
using MLDSA44Verify = MLDSAVerify<LogicCircuit, Field, ml_dsa::MLDsa44Params>;

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_H_
