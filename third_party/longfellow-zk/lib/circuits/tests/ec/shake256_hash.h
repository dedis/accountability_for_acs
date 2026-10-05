// SHAKE256 with a 32-byte output, for the post-quantum (PROOFS_EC_SHAKE256)
// build of the EC benchmarks: the circuit gadget, the native hash and its
// witness, and the input filling. Not upstream.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_SHAKE256_HASH_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_SHAKE256_HASH_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/dense.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "util/panic.h"

#include "openssl/evp.h"

namespace proofs {

constexpr size_t kShake256DigestBytes = 32;
constexpr size_t kShake256Rate = 136;

// Keccak-f calls for an n-byte message and a 32-byte output.
constexpr size_t shake256_blocks(size_t msg_bytes) {
  return (msg_bytes + kShake256Rate) / kShake256Rate;
}

inline std::array<uint8_t, kShake256DigestBytes> shake256(const uint8_t* msg,
                                                          size_t n) {
  std::array<uint8_t, kShake256DigestBytes> out{};
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  check(ctx != nullptr, "EVP_MD_CTX_new failed");
  check(EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) == 1 &&
            EVP_DigestUpdate(ctx, msg, n) == 1 &&
            EVP_DigestFinalXOF(ctx, out.data(), out.size()) == 1,
        "SHAKE256 failed");
  EVP_MD_CTX_free(ctx);
  return out;
}

// One SHAKE256 evaluation, with the Keccak block witnesses the circuit needs.
struct Shake256Native {
  std::vector<Sha3Witness::BlockWitness> bws;
  std::array<uint8_t, kShake256DigestBytes> digest{};

  void compute(const uint8_t* msg, size_t n) {
    bws.clear();  // compute_witness_shake256 appends.
    Sha3Witness::compute_witness_shake256(std::vector<uint8_t>(msg, msg + n),
                                          kShake256DigestBytes, bws);
    // The digest is the first 32 bytes of the final state: lanes in x-major
    // order, little-endian within a lane (as assert_shake256 squeezes).
    for (size_t i = 0; i < kShake256DigestBytes; ++i) {
      const size_t lane = i / 8;
      digest[i] = static_cast<uint8_t>(
          bws.back().a_intermediate[23][lane % 5][lane / 5] >> (8 * (i % 8)));
    }
  }

  template <class Field>
  void push(DenseFiller<Field>& filler, const Field& f) const {
    Sha3Witness::fill_witness(filler, bws, f);
  }
};

// The circuit side: SHAKE256 of a fixed-length message of v8 wires.
template <class LogicCircuit>
class Shake256Hash {
 public:
  using v8 = typename LogicCircuit::v8;
  using BlockWitness = typename Sha3Circuit<LogicCircuit>::BlockWitness;

  // Block witnesses for one hash; input order matches Shake256Native::push.
  struct Witness {
    std::vector<BlockWitness> bws;
    void input(const LogicCircuit& lc, size_t msg_bytes) {
      bws.resize(shake256_blocks(msg_bytes));
      for (auto& bw : bws) bw.input(lc);
    }
  };

  explicit Shake256Hash(const LogicCircuit& lc) : sha3_(lc) {}

  std::array<v8, kShake256DigestBytes> digest(const v8* msg, size_t n,
                                              const Witness& w) {
    std::vector<v8> out;
    sha3_.assert_shake256(std::vector<v8>(msg, msg + n), kShake256DigestBytes,
                          out, w.bws);
    std::array<v8, kShake256DigestBytes> d;
    for (size_t i = 0; i < kShake256DigestBytes; ++i) d[i] = out[i];
    return d;
  }

 private:
  Sha3Circuit<LogicCircuit> sha3_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_SHAKE256_HASH_H_
