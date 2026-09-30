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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_CREDENTIAL_COMMITMENT_PROOF_PROVE_VERIFY_SHARED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_CREDENTIAL_COMMITMENT_PROOF_PROVE_VERIFY_SHARED_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "arrays/dense.h"
#include "ec/p256.h"

namespace proofs {

constexpr size_t kProveVerifyRate = 7;
constexpr size_t kProveVerifyQueries = 132;

extern const char kP256ExtRootX[];
extern const char kP256ExtRootY[];
constexpr uint64_t kP256ExtRootOrder = 1ull << 31;

// 32 attribute slots; flat SHA-256 over Merkle-style leaves SHA256(be32(i)||value_i);
// 5 slots used in the age-check presentation (0,1,4,5,6).
// C4 = ECDSA under IDu on SHA256(t || r2·pk_x || r2·pk_y).
constexpr size_t kProveVerifyCredentialAttrs = 32;
constexpr size_t kProveVerifyAttrBytes = 32;
constexpr size_t kProveVerifyCredentialMsgBytes = kProveVerifyCredentialAttrs * kProveVerifyAttrBytes;
constexpr size_t kProveVerifyCredentialShaBlocks = 17;
constexpr size_t kProveVerifyTagMsgBytes = 3 * 32;
constexpr size_t kProveVerifyTagShaBlocks = 2;
constexpr size_t kProveVerifyTsBits = 43;

struct P256Traits {
  using Field = Fp256Base;
  using Scalar = Fp256Scalar;
  using EC = P256;

  static const EC& ec();
  static const Field& field();
  static const Scalar& scalar_field();
};

constexpr size_t kProveVerifyPubIdxIssuerX = 1;
constexpr size_t kProveVerifyPubIdxIssuerY = 2;
constexpr size_t kProveVerifyPubIdxElgamalX = 3;
constexpr size_t kProveVerifyPubIdxElgamalY = 4;
constexpr size_t kProveVerifyPubIdxT = 5;
constexpr size_t kProveVerifyPubIdxC1x = 6;
constexpr size_t kProveVerifyPubIdxC1y = 7;
constexpr size_t kProveVerifyPubIdxC2x = 8;
constexpr size_t kProveVerifyPubIdxC2y = 9;
constexpr size_t kProveVerifyPubIdxC3x = 10;
constexpr size_t kProveVerifyPubIdxC3y = 11;
constexpr size_t kProveVerifyPubIdxC4Rx = 12;
constexpr size_t kProveVerifyPubIdxC4Ry = 13;
constexpr size_t kProveVerifyPubIdxC4S = 14;
constexpr size_t kProveVerifyPubIdxNow = 15;
constexpr size_t kProveVerifyPubIdxMaxBirth = 16;

class CredentialCommitmentProveVerifyHarnessP256;

struct CredentialCommitmentProveVerifyHarnessP256Deleter {
  void operator()(CredentialCommitmentProveVerifyHarnessP256* p) const;
};

using CredentialCommitmentProveVerifyHarnessP256Ptr =
    std::unique_ptr<CredentialCommitmentProveVerifyHarnessP256,
                    CredentialCommitmentProveVerifyHarnessP256Deleter>;

CredentialCommitmentProveVerifyHarnessP256Ptr MakeCredentialCommitmentProveVerifyHarnessP256(
    size_t numInstances);

// Synthetic credential prep split for realistic benchmarking:
// init_credential_once() runs in the harness constructor (issuance, untracked per show);
// refresh_show_inputs() runs each presentation inside prove_ns.
void RebuildBenchmarkCredentialP256(CredentialCommitmentProveVerifyHarnessP256& h);

bool ProveVerifyP256(CredentialCommitmentProveVerifyHarnessP256& h);
std::unique_ptr<Dense<Fp256Base>> PublicInputsProveVerifyP256(
    const CredentialCommitmentProveVerifyHarnessP256& h);
bool VerifyProveVerifyP256(const CredentialCommitmentProveVerifyHarnessP256& h,
                          const Dense<Fp256Base>& pub);
/** Serialized ZkProof::write size after a successful Prove(); 0 if no proof. */
size_t ProofWireBytesProveVerifyP256(const CredentialCommitmentProveVerifyHarnessP256& h);

inline bool ProveAndVerifyProveVerifyP256(CredentialCommitmentProveVerifyHarnessP256& h) {
  if (!ProveVerifyP256(h)) return false;
  auto pub = PublicInputsProveVerifyP256(h);
  return VerifyProveVerifyP256(h, *pub);
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_CREDENTIAL_COMMITMENT_PROOF_PROVE_VERIFY_SHARED_H_
