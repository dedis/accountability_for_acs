// ML-DSA and SLH-DSA key generation and signing with OpenSSL 3.5 or newer
// (not upstream), for the witnesses of the credential proofs. Pure
// signatures with an empty context (FIPS 204 Alg. 2, FIPS 205 Alg. 22).

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_OSSL_SIG_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_OSSL_SIG_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "openssl/evp.h"
#include "openssl/opensslv.h"
#include "util/panic.h"

static_assert(OPENSSL_VERSION_NUMBER >= 0x30500000L,
              "ML-DSA and SLH-DSA need OpenSSL 3.5 or newer");

namespace proofs {
namespace pq_cred {

class OsslKey {
 public:
  // ALG: an OpenSSL algorithm name, e.g. "ML-DSA-65" or
  // "SLH-DSA-SHAKE-192s".
  explicit OsslKey(const char* alg) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, alg, nullptr);
    check(ctx != nullptr, "unknown signature algorithm");
    EVP_PKEY* key = nullptr;
    const bool ok =
        EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_generate(ctx, &key) == 1;
    EVP_PKEY_CTX_free(ctx);
    check(ok, "key generation failed");
    key_.reset(key);
    size_t len = 0;
    check(EVP_PKEY_get_raw_public_key(key, nullptr, &len) == 1,
          "public key length");
    pk_.resize(len);
    check(EVP_PKEY_get_raw_public_key(key, pk_.data(), &len) == 1 &&
              len == pk_.size(),
          "public key");
  }

  const std::vector<uint8_t>& pk() const { return pk_; }

  std::vector<uint8_t> sign(const std::vector<uint8_t>& msg) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    check(ctx != nullptr, "EVP_MD_CTX_new");
    size_t len = 0;
    bool ok = EVP_DigestSignInit_ex(ctx, nullptr, nullptr, nullptr, nullptr,
                                    key_.get(), nullptr) == 1 &&
              EVP_DigestSign(ctx, nullptr, &len, msg.data(), msg.size()) == 1;
    std::vector<uint8_t> sig(len);
    ok = ok &&
         EVP_DigestSign(ctx, sig.data(), &len, msg.data(), msg.size()) == 1;
    EVP_MD_CTX_free(ctx);
    check(ok, "signing failed");
    sig.resize(len);
    return sig;
  }

 private:
  struct Free {
    void operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); }
  };
  std::unique_ptr<EVP_PKEY, Free> key_;
  std::vector<uint8_t> pk_;
};

}  // namespace pq_cred
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_OSSL_SIG_H_
