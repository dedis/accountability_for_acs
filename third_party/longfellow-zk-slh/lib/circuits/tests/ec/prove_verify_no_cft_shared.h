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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_CREDENTIAL_COMMITMENT_PROOF_FLAT32_NO_CFT_SHARED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_CREDENTIAL_COMMITMENT_PROOF_FLAT32_NO_CFT_SHARED_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "arrays/dense.h"
#include "ec/p256.h"

namespace proofs {

// Same Longfellow proving parameters as the flat32 benchmark; only circuit logic differs.
constexpr size_t kProveVerifyNoCftRate = 7;
constexpr size_t kProveVerifyNoCftQueries = 132;

extern const char kP256ExtRootX[];
extern const char kP256ExtRootY[];
constexpr uint64_t kP256ExtRootOrder = 1ull << 31;

// 32 attribute slots; flat SHA-256 over Merkle-style leaves SHA256(be32(i)||value_i);
// 5 slots used (4,5,6,14,15). Slot index is in the leaf (not a UTF-8 claim label).
constexpr size_t kProveVerifyNoCftCredentialAttrs = 32;
constexpr size_t kProveVerifyNoCftAttrBytes = 32;
constexpr size_t kProveVerifyNoCftCredentialMsgBytes =
    kProveVerifyNoCftCredentialAttrs * kProveVerifyNoCftAttrBytes;
constexpr size_t kProveVerifyNoCftCredentialShaBlocks = 17;
constexpr size_t kProveVerifyNoCftTsBits = 43;

struct P256Traits {
  using Field = Fp256Base;
  using Scalar = Fp256Scalar;
  using EC = P256;

  static const EC& ec();
  static const Field& field();
  static const Scalar& scalar_field();
};

// Public input layout (first "dummy" is always present in Longfellow circuits).
constexpr size_t kProveVerifyNoCftPubIdxIssuerX = 1;
constexpr size_t kProveVerifyNoCftPubIdxIssuerY = 2;
constexpr size_t kProveVerifyNoCftPubIdxM = 3;
constexpr size_t kProveVerifyNoCftPubIdxNow = 4;
constexpr size_t kProveVerifyNoCftPubIdxMaxBirth = 5;

class CredentialCommitmentProveVerifyNoCftHarnessP256;

struct CredentialCommitmentProveVerifyNoCftHarnessP256Deleter {
  void operator()(CredentialCommitmentProveVerifyNoCftHarnessP256* p) const;
};

using CredentialCommitmentProveVerifyNoCftHarnessP256Ptr =
    std::unique_ptr<CredentialCommitmentProveVerifyNoCftHarnessP256,
                    CredentialCommitmentProveVerifyNoCftHarnessP256Deleter>;

CredentialCommitmentProveVerifyNoCftHarnessP256Ptr
MakeCredentialCommitmentProveVerifyNoCftHarnessP256(size_t numInstances);

void RebuildBenchmarkCredentialNoCftP256(CredentialCommitmentProveVerifyNoCftHarnessP256& h);

bool ProveVerifyNoCftP256(CredentialCommitmentProveVerifyNoCftHarnessP256& h);
std::unique_ptr<Dense<Fp256Base>> PublicInputsProveVerifyNoCftP256(
    const CredentialCommitmentProveVerifyNoCftHarnessP256& h);
bool VerifyProveVerifyNoCftP256(const CredentialCommitmentProveVerifyNoCftHarnessP256& h,
                           const Dense<Fp256Base>& pub);

inline bool ProveAndVerifyProveVerifyNoCftP256(
    CredentialCommitmentProveVerifyNoCftHarnessP256& h) {
  if (!ProveVerifyNoCftP256(h)) return false;
  auto pub = PublicInputsProveVerifyNoCftP256(h);
  return VerifyProveVerifyNoCftP256(h, *pub);
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_CREDENTIAL_COMMITMENT_PROOF_FLAT32_NO_CFT_SHARED_H_

