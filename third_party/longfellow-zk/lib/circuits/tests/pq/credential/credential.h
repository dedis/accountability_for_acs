// The credential of the post-quantum credential proofs (not upstream).
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!  Experimental research code.
//
// As the classical benchmark (circuits/tests/ec/prove_verify_shared.h): 32
// attributes of 32 bytes; leaf i = SHAKE256(be32(i) || attribute i); the
// credential digest D = SHAKE256(leaf 0 || ... || leaf 31), signed by the
// issuer. Digests have kHashDigestSize bytes (48 for category 3, 64 for
// category 5). The proof computes the leaves of the attributes it uses;
// the other leaves are private inputs. Used attributes:
//
//   4, 5, 6   birth, valid from, valid until: 43-bit timestamps, big-endian
//   14, 15    without CFT: ID of the hardware key, bytes 0-31 and 32-63
//   0, 1      with CFT: ID of the user (C4) key, bytes 0-31 and 32-63
//
// ID = SHAKE256(public key, 64 bytes): tr for ML-DSA (FIPS 204, Alg. 8).

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_CREDENTIAL_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_CREDENTIAL_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/tests/pq/credential/age.h"
#include "circuits/tests/pq/credential/sponge.h"
#include "circuits/tests/pq/credential/statement.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "random/random.h"
#include "util/crypto.h"
#include "util/panic.h"

namespace proofs {
namespace pq_cred {

constexpr size_t kAttrs = 32;
constexpr size_t kAttrBytes = 32;
constexpr size_t kIdBytes = 64;
constexpr size_t kSlotBirth = 4, kSlotValidFrom = 5, kSlotValidUntil = 6;

inline size_t id_slot(bool cft) { return cft ? 0 : 14; }

inline std::vector<uint8_t> shake256(const std::vector<uint8_t>& in,
                                     size_t out) {
  std::vector<uint8_t> r(out);
  Sha3Reference::shake256Hash(in.data(), in.size(), r.data(), out);
  return r;
}

// A SHAKE256 digest of kHashDigestSize bytes.
using HashBytes = std::array<uint8_t, kHashDigestSize>;

inline HashBytes shake256_digest(const std::vector<uint8_t>& in) {
  HashBytes r;
  Sha3Reference::shake256Hash(in.data(), in.size(), r.data(), r.size());
  return r;
}

// The event tag of a presentation request, from its public transcript:
// t = SHAKE256(be64(TS) || RID || VERIFIER), kHashDigestSize bytes. C4
// signs it, which binds a presentation to one request of one verifier.
inline HashBytes event_tag(uint64_t ts, const std::array<uint8_t, 32>& rid,
                           const std::array<uint8_t, 32>& verifier) {
  std::vector<uint8_t> in(8);
  for (size_t i = 0; i < 8; ++i) in[i] = static_cast<uint8_t>(ts >> (56 - 8 * i));
  in.insert(in.end(), rid.begin(), rid.end());
  in.insert(in.end(), verifier.begin(), verifier.end());
  return shake256_digest(in);
}

// The message C4 signs: SHAKE256(T || R2).
inline std::vector<uint8_t> c4_message(const HashBytes& t,
                                       const std::array<uint8_t, 32>& r2) {
  std::vector<uint8_t> in(t.begin(), t.end());
  in.insert(in.end(), r2.begin(), r2.end());
  return shake256(in, kHashDigestSize);
}

// H = SHAKE256(ID || R2), the public binding of a CFT to the message it
// encrypts; the fresh, private, 256-bit R2 hides ID. After opening, the
// authorities check the opened ID || R2 against it: a mismatch shows that
// an authority changed its decryption share.
inline HashBytes cft_binding(const std::vector<uint8_t>& id,
                             const std::array<uint8_t, 32>& r2) {
  std::vector<uint8_t> in(id);
  in.insert(in.end(), r2.begin(), r2.end());
  return shake256_digest(in);
}

// NOW and MAX_BIRTH fit the kTsBits bits the age circuit compares; a
// verifier rejects other values, which the circuit would truncate.
inline bool timestamps_fit(uint64_t now, uint64_t max_birth) {
  return now < (uint64_t(1) << kTsBits) && max_birth < (uint64_t(1) << kTsBits);
}

struct Credential {
  std::array<std::array<uint8_t, kAttrBytes>, kAttrs> attr{};

  // Random attributes, the timestamps of TS and the identity ID.
  static Credential make(const Timestamps& ts,
                         const std::vector<uint8_t>& id, bool cft,
                         RandomEngine& rng) {
    check(id.size() == kIdBytes, "ID length");
    Credential c;
    for (auto& a : c.attr) rng.bytes(a.data(), a.size());
    c.put_ts(kSlotBirth, ts.birth);
    c.put_ts(kSlotValidFrom, ts.valid_from);
    c.put_ts(kSlotValidUntil, ts.valid_until);
    const size_t s = id_slot(cft);
    for (size_t i = 0; i < kAttrBytes; ++i) {
      c.attr[s][i] = id[i];
      c.attr[s + 1][i] = id[kAttrBytes + i];
    }
    return c;
  }

  void put_ts(size_t slot, uint64_t x) {
    check(x < (uint64_t(1) << kTsBits), "timestamp range");
    attr[slot].fill(0);
    for (size_t i = 0; i < 8; ++i) attr[slot][31 - i] = uint8_t(x >> (8 * i));
  }

  std::vector<uint8_t> leaf(size_t i) const {
    std::vector<uint8_t> in(64, 0);
    in[31] = static_cast<uint8_t>(i);
    for (size_t k = 0; k < kAttrBytes; ++k) in[32 + k] = attr[i][k];
    return shake256(in, kHashDigestSize);
  }

  std::vector<uint8_t> digest() const {
    std::vector<uint8_t> in;
    in.reserve(kAttrs * kHashDigestSize);
    for (size_t i = 0; i < kAttrs; ++i) {
      const auto l = leaf(i);
      in.insert(in.end(), l.begin(), l.end());
    }
    return shake256(in, kHashDigestSize);
  }
};

// The credential in the sponge: the digest D, and the timestamp bits
// (birth, valid from, valid until; LSB first) for the age part.
struct CredentialRefs {
  Bytes digest;
  std::array<std::vector<Bit>, 3> ts;
};

// Hashes the used leaves of C (zeros for the verifier) and D. ID: the 64
// ID bytes, references to their definition. ID_VALUES_FROM_CREDENTIAL, for
// tests only: the ID attribute bits keep their references to ID but take
// their native values from C, the witness of a cheating prover that breaks
// only these links.
template <class Field>
CredentialRefs hash_credential(Sponge<Field>& sp, const Credential& c,
                               const Bytes& id, bool cft,
                               bool id_values_from_credential = false) {
  check(id.size() == 8 * kIdBytes, "ID length");
  CredentialRefs r;
  const size_t sid = id_slot(cft);
  const size_t ts_slot[3] = {kSlotBirth, kSlotValidFrom, kSlotValidUntil};
  Bytes leaves;
  leaves.reserve(8 * kAttrs * kHashDigestSize);
  for (size_t i = 0; i < kAttrs; ++i) {
    size_t ts = 3;
    for (size_t k = 0; k < 3; ++k) ts = ts_slot[k] == i ? k : ts;
    if (ts == 3 && i != sid && i != sid + 1) {
      const auto l = c.leaf(i);
      const Bytes v = free_bytes(l.data(), l.size());
      leaves.insert(leaves.end(), v.begin(), v.end());
      continue;
    }
    uint8_t name[32] = {};
    name[31] = static_cast<uint8_t>(i);
    Bytes attr;
    if (ts == 3) {
      attr = slice(id, i == sid ? 0 : kAttrBytes, kAttrBytes);
      if (id_values_from_credential) {
        for (size_t k = 0; k < attr.size(); ++k) {
          attr[k].value = (c.attr[i][k / 8] >> (k % 8)) & 1;
        }
      }
    } else {
      // Big-endian; the bits above kTsBits are zero.
      attr = const_bytes(c.attr[i].data(), kAttrBytes);
      for (size_t t = 0; t < kTsBits; ++t) {
        Bit& b = attr[8 * (kAttrBytes - 1 - t / 8) + t % 8];
        b = Bit::free(b.value);
      }
      for (size_t t = kTsBits; t < 8 * kAttrBytes; ++t) {
        Bit& b = attr[8 * (kAttrBytes - 1 - t / 8) + t % 8];
        check(!b.value, "timestamp attribute above 43 bits");
      }
    }
    const Bytes nm = const_bytes(name, sizeof(name));
    Bytes in;
    const Bytes leaf = sp.shake(kShake256Rate, cat({&nm, &attr}),
                                kHashDigestSize, &in);
    if (ts < 3) {
      for (size_t t = 0; t < kTsBits; ++t) {
        r.ts[ts].push_back(in[8 * (32 + kAttrBytes - 1 - t / 8) + t % 8]);
      }
    }
    leaves.insert(leaves.end(), leaf.begin(), leaf.end());
  }
  r.digest = sp.shake(kShake256Rate, leaves, kHashDigestSize);
  return r;
}

}  // namespace pq_cred
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_CREDENTIAL_H_
