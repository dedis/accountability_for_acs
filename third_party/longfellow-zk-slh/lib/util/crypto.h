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

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_

// Encapsulates all of the cryptographic primitives used by this library.
// Specifically, for the collision-resistant hash function, this library uses
// SHA256. For a pseudo-random function, this library uses AES in ECB mode.
// Finally, this library provides a method to generate random bytes using the
// openssl library.
//
// With PROOFS_SHAKE256 (the post-quantum build; not upstream), Hash is SHAKE256
// with a 48-byte output (192-bit collision resistance: NIST category 3 or 4,
// not 5; PROOFS_SHAKE256_DIGEST_BYTES=64 gives 256 bits for category 5) and
// PRF is keyed SHAKE256. Every translation unit of a program must agree on
// PROOFS_SHAKE256 and PROOFS_SHAKE256_DIGEST_BYTES.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "util/panic.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/aes.h"

namespace proofs {

constexpr size_t kSHA256DigestSize = 32;
// 48 bytes (192-bit collisions) by default; 64 for NIST category 5.
#ifndef PROOFS_SHAKE256_DIGEST_BYTES
#define PROOFS_SHAKE256_DIGEST_BYTES 48
#endif
constexpr size_t kSHAKE256DigestSize = PROOFS_SHAKE256_DIGEST_BYTES;
constexpr size_t kPRFInputSize = 16;

class SHA256 {
 public:
  SHA256() { SHA256_Init(&sha_); }

  // Disable copy for good measure.
  SHA256(const SHA256&) = delete;
  SHA256& operator=(const SHA256&) = delete;

  void Update(const uint8_t bytes[/*n*/], size_t n) { SHA256_Update(&sha_, bytes, n); }
  void DigestData(uint8_t digest[/* kSHA256DigestSize */]) {
    SHA256_Final(digest, &sha_);
  }
  void CopyState(const SHA256& src) { sha_ = src.sha_; }

  void Update8(uint64_t x) {
    uint8_t buf[8];
    for (size_t i = 0; i < 8; ++i) {
      buf[i] = x & 0xff;
      x >>= 8;
    }
    Update(buf, 8);
  }

 private:
  SHA256_CTX sha_;
};

// SHAKE256 with a 48-byte output, with the interface of SHA256. Not upstream.
class SHAKE256 {
 public:
  SHAKE256() : ctx_(EVP_MD_CTX_new()) {
    check(ctx_ != nullptr, "EVP_MD_CTX_new failed");
    check(EVP_DigestInit_ex(ctx_, EVP_shake256(), nullptr) == 1,
          "EVP_DigestInit_ex failed");
  }

  ~SHAKE256() { EVP_MD_CTX_free(ctx_); }

  SHAKE256(const SHAKE256&) = delete;
  SHAKE256& operator=(const SHAKE256&) = delete;

  void Update(const uint8_t bytes[/*n*/], size_t n) {
    check(EVP_DigestUpdate(ctx_, bytes, n) == 1, "EVP_DigestUpdate failed");
  }
  void DigestData(uint8_t digest[/* kSHAKE256DigestSize */]) {
    check(EVP_DigestFinalXOF(ctx_, digest, kSHAKE256DigestSize) == 1,
          "EVP_DigestFinalXOF failed");
  }
  void CopyState(const SHAKE256& src) {
    check(EVP_MD_CTX_copy_ex(ctx_, src.ctx_) == 1, "EVP_MD_CTX_copy_ex failed");
  }

  void Update8(uint64_t x) {
    uint8_t buf[8];
    for (size_t i = 0; i < 8; ++i) {
      buf[i] = x & 0xff;
      x >>= 8;
    }
    Update(buf, 8);
  }

 private:
  EVP_MD_CTX* ctx_;
};

// A pseudo-random function interface. This implementation uses AES in ECB mode.
// The caller must ensure that arguments are not reused.
class AesPRF {
 public:
  static constexpr size_t kKeySize = 32;
  static constexpr size_t kOutputSize = 16;

  explicit AesPRF(const uint8_t key[/*kKeySize*/]) {
    ctx_ = EVP_CIPHER_CTX_new();
    int ret =
        EVP_EncryptInit_ex(ctx_, EVP_aes_256_ecb(), nullptr, key, nullptr);
    check(ret == 1, "EVP_EncryptInit_ex failed");
  }

  ~AesPRF() { EVP_CIPHER_CTX_free(ctx_); }

  // Disable copy for good measure.
  AesPRF(const AesPRF&) = delete;
  AesPRF& operator=(const AesPRF&) = delete;

  // Evaluate the PRF on the input and write the output to the output buffer.
  // This method should only be used internally by the Transcript class. The
  // caller must ensure that the input and output buffers are different.
  // This function implements a permutation, but we only need to exploit its
  // pseudo-random function property in this application.
  void Eval(uint8_t out[/*kOutputSize*/], uint8_t in[/*kPRFInputSize*/]) {
    int out_len = static_cast<int>(kOutputSize);
    int ret = EVP_EncryptUpdate(ctx_, out, &out_len, in,
                                static_cast<int>(kPRFInputSize));
    check(ret == 1, "EVP_EncryptUpdate failed");
  }

 private:
  EVP_CIPHER_CTX* ctx_;
};

// A pseudo-random function: SHAKE256(key || in), squeezed to one rate block
// (136 bytes), so that one Keccak-f call yields the whole output. Not upstream.
// The caller must ensure that arguments are not reused.
class ShakePRF {
 public:
  static constexpr size_t kKeySize = kSHAKE256DigestSize;
  static constexpr size_t kOutputSize = 136;

  explicit ShakePRF(const uint8_t key[/*kKeySize*/])
      : keyed_(EVP_MD_CTX_new()), ctx_(EVP_MD_CTX_new()) {
    check(keyed_ != nullptr && ctx_ != nullptr, "EVP_MD_CTX_new failed");
    check(EVP_DigestInit_ex(keyed_, EVP_shake256(), nullptr) == 1 &&
              EVP_DigestUpdate(keyed_, key, kKeySize) == 1,
          "SHAKE256 PRF key setup failed");
  }

  ~ShakePRF() {
    EVP_MD_CTX_free(ctx_);
    EVP_MD_CTX_free(keyed_);
  }

  ShakePRF(const ShakePRF&) = delete;
  ShakePRF& operator=(const ShakePRF&) = delete;

  void Eval(uint8_t out[/*kOutputSize*/], uint8_t in[/*kPRFInputSize*/]) {
    check(EVP_MD_CTX_copy_ex(ctx_, keyed_) == 1 &&
              EVP_DigestUpdate(ctx_, in, kPRFInputSize) == 1 &&
              EVP_DigestFinalXOF(ctx_, out, kOutputSize) == 1,
          "SHAKE256 PRF failed");
  }

 private:
  EVP_MD_CTX* keyed_;  // has absorbed the key
  EVP_MD_CTX* ctx_;    // one evaluation
};

#ifdef PROOFS_SHAKE256
using Hash = SHAKE256;
using PRF = ShakePRF;
constexpr size_t kHashDigestSize = kSHAKE256DigestSize;
#else
using Hash = SHA256;
using PRF = AesPRF;
constexpr size_t kHashDigestSize = kSHA256DigestSize;
#endif

// Generate n random bytes, following the openssl API convention.
// This method will panic if the openssl library fails.
void rand_bytes(uint8_t out[/*n*/], size_t n);

void hex_to_str(char out[/* 2*n + 1*/], const uint8_t in[/*n*/], size_t n);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_
