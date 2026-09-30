// Copyright 2026 Google LLC.
//
// ProveVerify + CFT + packed status-list revocation (SHA-256 Merkle).

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PROVE_VERIFY_REVOCATION_SHARED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PROVE_VERIFY_REVOCATION_SHARED_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "arrays/dense.h"
#include "ec/p256.h"

namespace proofs {

constexpr size_t kProveVerifyRevocRate = 7;
constexpr size_t kProveVerifyRevocQueries = 132;

constexpr size_t kProveVerifyRevocCredentialAttrs = 32;
constexpr size_t kProveVerifyRevocAttrBytes = 32;
constexpr size_t kProveVerifyRevocCredentialMsgBytes =
    kProveVerifyRevocCredentialAttrs * kProveVerifyRevocAttrBytes;
constexpr size_t kProveVerifyRevocCredentialShaBlocks = 17;
constexpr size_t kProveVerifyRevocTagMsgBytes = 3 * 32;
constexpr size_t kProveVerifyRevocTagShaBlocks = 2;
constexpr size_t kProveVerifyRevocTsBits = 43;
constexpr size_t kProveVerifyRevocSlot = 14;
constexpr size_t kProveVerifyRevocBitsPerLeaf = 253;

// Public inputs: same as ProveVerify (17 incl. dummy) + 32 root bytes.
constexpr size_t kProveVerifyRevocPublicSize = 17 + 32;

class ProveVerifyRevocationHarnessP256;
struct ProveVerifyRevocationHarnessP256Deleter {
  void operator()(ProveVerifyRevocationHarnessP256* p) const;
};

using ProveVerifyRevocationHarnessP256Ptr =
    std::unique_ptr<ProveVerifyRevocationHarnessP256,
                    ProveVerifyRevocationHarnessP256Deleter>;

// revoc_log2 ∈ {12,16,20,24} → packed Merkle depth {5,9,13,17}
ProveVerifyRevocationHarnessP256Ptr MakeProveVerifyRevocationHarnessP256(
    size_t revoc_log2);

// Per-show: refresh CFT trail (+ rebuild Merkle path for the issued index).
void RefreshProveVerifyRevocationShowP256(ProveVerifyRevocationHarnessP256& h);

bool ProveProveVerifyRevocationP256(ProveVerifyRevocationHarnessP256& h);
std::unique_ptr<Dense<Fp256Base>> PublicInputsProveVerifyRevocationP256(
    const ProveVerifyRevocationHarnessP256& h);
bool VerifyProveVerifyRevocationP256(const ProveVerifyRevocationHarnessP256& h,
                                     const Dense<Fp256Base>& pub);
/** Serialized ZkProof::write size after a successful Prove(); 0 if no proof. */
size_t ProofWireBytesProveVerifyRevocationP256(
    ProveVerifyRevocationHarnessP256& h);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PROVE_VERIFY_REVOCATION_SHARED_H_
