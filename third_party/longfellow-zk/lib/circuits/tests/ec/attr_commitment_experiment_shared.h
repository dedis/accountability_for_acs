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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_ATTR_COMMITMENT_EXPERIMENT_SHARED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_ATTR_COMMITMENT_EXPERIMENT_SHARED_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "arrays/dense.h"
#include "ec/p256.h"

namespace proofs {

// Opaque benchmark harness: owns circuit/prover/witness and can run prove().
class AttrCommitmentExperimentHarnessP256;
struct AttrCommitmentExperimentHarnessP256Deleter {
  void operator()(AttrCommitmentExperimentHarnessP256* p) const;
};

using AttrCommitmentExperimentHarnessP256Ptr =
    std::unique_ptr<AttrCommitmentExperimentHarnessP256,
                    AttrCommitmentExperimentHarnessP256Deleter>;

// mode: "flat" or "merkle"
AttrCommitmentExperimentHarnessP256Ptr MakeAttrCommitmentExperimentHarnessP256(
    const char* mode, size_t total_attrs, size_t revealed_attrs);

// Runs one prove (commit+prove) for the configured mode/params.
bool ProveAttrCommitmentExperimentP256(AttrCommitmentExperimentHarnessP256& h);

// Build a public input vector corresponding to the current harness instance.
std::unique_ptr<Dense<Fp256Base>> PublicInputsAttrCommitmentExperimentP256(
    const AttrCommitmentExperimentHarnessP256& h);

// Verify the already-produced proof against the provided public inputs.
bool VerifyAttrCommitmentExperimentP256(const AttrCommitmentExperimentHarnessP256& h,
                                       const Dense<Fp256Base>& pub);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_ATTR_COMMITMENT_EXPERIMENT_SHARED_H_

