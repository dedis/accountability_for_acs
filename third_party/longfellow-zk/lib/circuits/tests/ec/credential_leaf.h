// The leaf hashes of the used credential attributes, in the circuit (not
// upstream): leaf i = H(be32(i) || attribute i), with H SHA-256 or, with
// PROOFS_EC_SHAKE256, SHAKE256 (48 bytes). The circuit asserts that the
// leaf equals the leaf digest that the credential hash reads, so the
// attribute values the proof uses are bound to the issuer-signed digest.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_CREDENTIAL_LEAF_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_CREDENTIAL_LEAF_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "arrays/dense.h"
#include "util/panic.h"
#ifdef PROOFS_EC_SHAKE256
#include "circuits/tests/ec/shake256_hash.h"
#else
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#endif

namespace proofs {

// The 64-byte leaf message be32(SLOT) || ATTR.
inline std::array<uint8_t, 64> leaf_message(size_t slot,
                                            const uint8_t attr[32]) {
  std::array<uint8_t, 64> m{};
  m[31] = static_cast<uint8_t>(slot);
  std::memcpy(m.data() + 32, attr, 32);
  return m;
}

#ifdef PROOFS_EC_SHAKE256

template <class LogicCircuit>
class LeafHash {
  using v8 = typename LogicCircuit::v8;
  using Hash = Shake256Hash<LogicCircuit>;

 public:
  struct Witness {
    typename Hash::Witness hash;
    void input(const LogicCircuit& lc) { hash.input(lc, 64); }
  };

  // LEAF: the kSHAKE256DigestSize leaf bytes that the credential hash reads.
  static void assert_leaf(const LogicCircuit& lc, size_t slot,
                          const v8 attr[32], const v8 leaf[], const Witness& w) {
    v8 msg[64];
    for (size_t i = 0; i < 32; ++i) {
      msg[i] = lc.template vbit<8>(i == 31 ? slot : 0);
      msg[32 + i] = attr[i];
    }
    Hash h(lc);
    const auto d = h.digest(msg, 64, w.hash);
    for (size_t i = 0; i < kSHAKE256DigestSize; ++i) lc.vassert_eq(d[i], leaf[i]);
  }
};

struct LeafNative {
  Shake256Native hash;
  void compute(size_t slot, const uint8_t attr[32]) {
    const auto m = leaf_message(slot, attr);
    hash.compute(m.data(), m.size());
  }
  template <class Field>
  void push(DenseFiller<Field>& filler, const Field& f) const {
    hash.push(filler, f);
  }
};

#else

// FLATSHA: the FlatSHA256Circuit of the caller, with bit plucking PLUCKER.
template <class LogicCircuit, class Flatsha>
class LeafHash {
  using v8 = typename LogicCircuit::v8;

 public:
  struct Witness {
    typename Flatsha::BlockWitness bw[2];
    void input(const LogicCircuit& lc) {
      for (auto& b : bw) b.input(lc);
    }
  };

  // LEAF: the 32 leaf bytes that the credential hash reads.
  static void assert_leaf(const LogicCircuit& lc, const Flatsha& sha,
                          size_t slot, const v8 attr[32], const v8 leaf[],
                          const Witness& w) {
    // The 64-byte message and its padding: one more block, 0x80, zeros,
    // and the length 512 (bits) big-endian.
    v8 in[128];
    for (size_t i = 0; i < 32; ++i) {
      in[i] = lc.template vbit<8>(i == 31 ? slot : 0);
      in[32 + i] = attr[i];
    }
    for (size_t i = 64; i < 128; ++i) {
      const uint8_t pad = i == 64 ? 0x80 : i == 126 ? 0x02 : 0x00;
      in[i] = lc.template vbit<8>(pad);
    }
    sha.assert_message(2, lc.template vbit<8>(2), in, w.bw);
    // Byte 4 j + b of the digest is bits 24 - 8 b .. 31 - 8 b of word j.
    for (size_t j = 0; j < 8; ++j) {
      const auto hj = sha.bp_.unpack_v32(w.bw[1].h1[j]);
      for (size_t k = 0; k < 32; ++k) {
        lc.assert_eq(hj[k], leaf[4 * j + 3 - k / 8][k % 8]);
      }
    }
  }
};

template <size_t kPluckerBits>
struct LeafNativeT {
  std::array<FlatSHA256Witness::BlockWitness, 2> bw{};
  void compute(size_t slot, const uint8_t attr[32]) {
    const auto m = leaf_message(slot, attr);
    std::array<uint8_t, 128> padded{};
    uint8_t nb = 0;
    FlatSHA256Witness::transform_and_witness_message(64, m.data(), 2, nb,
                                                     padded.data(), bw.data());
    check(nb == 2, "leaf SHA-256 blocks");
  }
  template <class Field>
  void push(DenseFiller<Field>& filler, const Field& f) const {
    BitPluckerEncoder<Field, kPluckerBits> enc(f);
    for (const auto& b : bw) {
      for (size_t k = 0; k < 48; ++k) filler.push_back(enc.mkpacked_v32(b.outw[k]));
      for (size_t k = 0; k < 64; ++k) {
        filler.push_back(enc.mkpacked_v32(b.oute[k]));
        filler.push_back(enc.mkpacked_v32(b.outa[k]));
      }
      for (size_t k = 0; k < 8; ++k) filler.push_back(enc.mkpacked_v32(b.h1[k]));
    }
  }
};
using LeafNative = LeafNativeT<3>;

#endif

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_CREDENTIAL_LEAF_H_
