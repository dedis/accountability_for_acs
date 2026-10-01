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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_65_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_65_WITNESS_H_

#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_witness.h"

namespace proofs {

using ml_dsa_65_witness = ml_dsa_witness<ml_dsa::MLDsa65Params>;

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_65_WITNESS_H_
