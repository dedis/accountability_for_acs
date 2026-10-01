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

#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "algebra/fp24.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_65_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "gtest/gtest.h"

namespace proofs {
namespace ml_dsa {
namespace {

template <typename Params>
struct MLDsaTestTraits;

// MLDsaTestTraits abstracts the differences between ML-DSA parameter sets in
// tests.
//
// Specializations of this traits class map generic names (like
// Traits::PublicKey or Traits::GetExamples()) to the correct version-specific
// types and functions.
//
// Combined with Google Test's TYPED_TEST_SUITE and TYPED_TEST (defined below),
// this allows us to write a single generic test implementation that is
// automatically instantiated and run for both ML-DSA-44 and ML-DSA-65.

template <>
struct MLDsaTestTraits<MLDsa44Params> {
  using PublicKey = typename MLDsaTypes<MLDsa44Params>::PublicKey;
  using Signature = typename MLDsaTypes<MLDsa44Params>::Signature;
  using MatrixA = typename MLDsaTypes<MLDsa44Params>::MatrixA;
  using RqK = typename MLDsaTypes<MLDsa44Params>::RqK;
  using RqL = typename MLDsaTypes<MLDsa44Params>::RqL;

  using SignatureExample = MlDsa44SignatureExample;
  using ByteInputOutput = MlDsa44ByteInputOutput;
  using PkDecodeTest = MlDsa44PkDecodeTest;
  using SigDecodeTest = MlDsa44SigDecodeTest;
  using W1EncodeTests = MlDsa44W1EncodeTests;

  static std::vector<SignatureExample> GetExamples() {
    return GetMlDsa44Examples();
  }
  static std::vector<SignatureExample> GetFailExamples() {
    return GetMlDsa44FailExamples();
  }
  static std::vector<ByteInputOutput> GetSampleInBallTests() {
    return ml_dsa::GetSampleInBallTests();
  }
  static std::vector<PkDecodeTest> GetPkDecodeTests() {
    return ml_dsa::GetPkDecodeTests();
  }
  static std::vector<SigDecodeTest> GetSigDecodeTests() {
    return ml_dsa::GetSigDecodeTests();
  }
  static std::vector<W1EncodeTests> GetW1EncodeTests() {
    return ml_dsa::GetW1EncodeTests();
  }
  static std::vector<UseHintTestCase> GetUseHintTestCases() {
    return ml_dsa::GetUseHintTestCases();
  }

  static const uint64_t (*ExpectedExpandAVectors()) [MLDsa44Params::L][N] {
    return reinterpret_cast<const uint64_t (*)[MLDsa44Params::L][N]>(
        ml_dsa::kExpectedExpandAVectors);
  }

  static std::vector<uint8_t> ExpandASeed() {
    return {0x5e, 0x1b, 0xad, 0xb2, 0x92, 0x27, 0x6b, 0x20, 0x2a, 0x6f, 0x6a,
            0xf9, 0x0e, 0x3c, 0xdc, 0xf6, 0xc1, 0xb5, 0xcc, 0x62, 0x60, 0xc0,
            0x1b, 0x74, 0x7d, 0xac, 0x61, 0x9f, 0xe1, 0x61, 0x30, 0x28};
  }
};

template <>
struct MLDsaTestTraits<MLDsa65Params> {
  using PublicKey = typename MLDsaTypes<MLDsa65Params>::PublicKey;
  using Signature = typename MLDsaTypes<MLDsa65Params>::Signature;
  using MatrixA = typename MLDsaTypes<MLDsa65Params>::MatrixA;
  using RqK = typename MLDsaTypes<MLDsa65Params>::RqK;
  using RqL = typename MLDsaTypes<MLDsa65Params>::RqL;

  using SignatureExample = ml_dsa_65::MlDsa65SignatureExample;
  using ByteInputOutput = ml_dsa_65::MlDsa65ByteInputOutput;
  using PkDecodeTest = ml_dsa_65::MlDsa65PkDecodeTest;
  using SigDecodeTest = ml_dsa_65::MlDsa65SigDecodeTest;
  using W1EncodeTests = ml_dsa_65::MlDsa65W1EncodeTests;

  static std::vector<SignatureExample> GetExamples() {
    return ml_dsa_65::GetMlDsa65Examples();
  }
  static std::vector<SignatureExample> GetFailExamples() {
    return ml_dsa_65::GetMlDsa65FailExamples();
  }
  static std::vector<ByteInputOutput> GetSampleInBallTests() {
    return ml_dsa_65::GetSampleInBallTests();
  }
  static std::vector<PkDecodeTest> GetPkDecodeTests() {
    return ml_dsa_65::GetPkDecodeTests();
  }
  static std::vector<SigDecodeTest> GetSigDecodeTests() {
    return ml_dsa_65::GetSigDecodeTests();
  }
  static std::vector<W1EncodeTests> GetW1EncodeTests() {
    return ml_dsa_65::GetW1EncodeTests();
  }
  static std::vector<ml_dsa_65::UseHintTestCase> GetUseHintTestCases() {
    return ml_dsa_65::GetUseHintTestCases();
  }

  static const uint64_t (*ExpectedExpandAVectors()) [MLDsa65Params::L][N] {
    return reinterpret_cast<const uint64_t (*)[MLDsa65Params::L][N]>(
        ml_dsa_65::kExpectedExpandAVectors);
  }

  static std::vector<uint8_t> ExpandASeed() {
    std::vector<uint8_t> seed(32);
    for (int i = 0; i < 32; ++i) seed[i] = i;
    return seed;
  }
};

template <typename Params>
typename MLDsaTypes<Params>::MatrixA MatrixAFromVectors(
    const uint64_t (*in)[Params::L][N]) {
  const Fp24& Fq = ml_dsa::Fq();
  typename MLDsaTypes<Params>::MatrixA A;
  for (size_t r = 0; r < Params::K; ++r) {
    for (size_t s = 0; s < Params::L; ++s) {
      for (size_t i = 0; i < N; ++i) {
        A[r][s][i] = Fq.of_scalar(in[r][s][i]);
      }
    }
  }
  return A;
}

template <typename Params>
typename MLDsaTypes<Params>::RqK ComputeWApprox(
    const typename MLDsaTypes<Params>::PublicKey& pub_key,
    const typename MLDsaTypes<Params>::RqL& z, const Rq& c) {
  const Fp24& Fq = ml_dsa::Fq();
  Rq c_ntt = c;
  Ntt(c_ntt);

  typename MLDsaTypes<Params>::RqL z_ntt = z;
  for (size_t i = 0; i < Params::L; ++i) {
    Ntt(z_ntt[i]);
  }

  typename MLDsaTypes<Params>::RqK t1_ntt = pub_key.t1;
  for (size_t i = 0; i < Params::K; ++i) {
    Ntt(t1_ntt[i]);
  }

  typename MLDsaTypes<Params>::RqK w_approx_ntt;
  for (size_t r = 0; r < Params::K; ++r) {
    Rq az_r;  // Sum for row r
    for (size_t j = 0; j < N; ++j) az_r[j] = Fq.zero();

    for (size_t s = 0; s < Params::L; ++s) {
      Rq prod = mulf(pub_key.a_hat[r][s], z_ntt[s]);
      az_r = addf(az_r, prod);
    }

    // Subtract c_ntt * t1_ntt[r] * 2^d
    Rq ct1 = mulf(c_ntt, t1_ntt[r]);
    Elt two_d = Fq.of_scalar(1 << D);
    ct1 = scalef(ct1, two_d);

    w_approx_ntt[r] = subf(az_r, ct1);
  }

  typename MLDsaTypes<Params>::RqK w_approx;
  for (size_t i = 0; i < Params::K; ++i) {
    w_approx[i] = w_approx_ntt[i];
    InvNtt(w_approx[i]);
  }
  return w_approx;
}

template <typename Params>
bool VerifySignature(const std::vector<uint8_t>& pkey,
                     const std::vector<uint8_t>& sig_bytes,
                     const std::vector<uint8_t>& msg,
                     const std::vector<uint8_t>& ctx) {
  const Fp24& Fq = ml_dsa::Fq();
  using Traits = MLDsaTestTraits<Params>;
  typename Traits::PublicKey pub_key = pkDecode<Params>(pkey);
  auto maybe_sig = sigDecode<Params>(sig_bytes);
  if (!maybe_sig.has_value()) return false;
  typename Traits::Signature sig = maybe_sig.value();
  std::vector<uint8_t> tr(pub_key.tr.begin(), pub_key.tr.end());

  auto maybe_m_prime = preprocess_message(msg, ctx);
  if (!maybe_m_prime.has_value()) return false;
  std::vector<uint8_t> m_prime = maybe_m_prime.value();

  std::vector<uint8_t> input = tr;
  input.insert(input.end(), m_prime.begin(), m_prime.end());
  std::array<uint8_t, 64> mu;
  H(input, mu);

  // check infinity norm of z
  for (size_t i = 0; i < Params::L; ++i) {
    for (size_t j = 0; j < N; ++j) {
      Elt e = sig.z[i][j];
      uint64_t val = Fq.from_montgomery(e).limb_[0];
      int64_t sval = static_cast<int64_t>(val);
      if (sval > Q / 2) sval -= Q;
      if (std::abs(sval) >= Params::gamma_1 - Params::beta) {
        return false;
      }
    }
  }

  Rq c = SampleInBall<Params>(sig.c_tilde);
  typename Traits::RqK w_approx = ComputeWApprox<Params>(pub_key, sig.z, c);

  typename Traits::RqK w1;
  const uint32_t b_w1 = (ml_dsa::Q - 1) / (2 * Params::gamma_2) - 1;
  for (size_t r = 0; r < Params::K; ++r) {
    for (size_t j = 0; j < N; ++j) {
      uint64_t val = Fq.from_montgomery(w_approx[r][j]).limb_[0];
      uint32_t w1_val = UseHint<Params>(sig.h[r][j], static_cast<int32_t>(val));
      if (w1_val > b_w1) {
        return false;
      }
      w1[r][j] = Fq.of_scalar(w1_val);
    }
  }

  auto w1_bytes = w1Encode<Params>(w1);
  std::vector<uint8_t> c_prime_input;
  c_prime_input.insert(c_prime_input.end(), mu.begin(), mu.end());
  c_prime_input.insert(c_prime_input.end(), w1_bytes.begin(), w1_bytes.end());

  std::array<uint8_t, Params::c_tilde_bytes> c_prime;
  H(c_prime_input, c_prime);

  return c_prime == sig.c_tilde;
}

TEST(MlDsaSharedTest, NttRoundTrip) {
  const Fp24& Fq = ml_dsa::Fq();
  Rq a;
  for (size_t i = 0; i < N; ++i) {
    a[i] = Fq.of_scalar(i * 12345 + 1);
  }
  Rq original = a;

  Ntt(a);
  InvNtt(a);

  for (size_t i = 0; i < N; ++i) {
    EXPECT_EQ(a[i], original[i]) << "Mismatch at " << i;
  }
}

template <typename T>
class MlDsaRefTest : public ::testing::Test {
 public:
  using Params = T;
  using Traits = MLDsaTestTraits<Params>;
};

using MLDsaTestTypes = ::testing::Types<MLDsa44Params, MLDsa65Params>;
TYPED_TEST_SUITE(MlDsaRefTest, MLDsaTestTypes);

TYPED_TEST(MlDsaRefTest, ExpandA) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  std::vector<uint8_t> rho = Traits::ExpandASeed();

  typename Traits::MatrixA A = ExpandA<Params>(rho);

  typename Traits::MatrixA expected_A =
      MatrixAFromVectors<Params>(Traits::ExpectedExpandAVectors());

  for (size_t r = 0; r < Params::K; ++r) {
    for (size_t s = 0; s < Params::L; ++s) {
      for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(A[r][s][i], expected_A[r][s][i])
            << "Mismatch at r=" << r << " s=" << s << " i=" << i;
      }
    }
  }
}

TYPED_TEST(MlDsaRefTest, SampleInBall) {
  const Fp24& Fq = ml_dsa::Fq();
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  auto tests = Traits::GetSampleInBallTests();
  for (size_t i = 0; i < tests.size(); ++i) {
    std::array<uint8_t, Params::c_tilde_bytes> rho_arr;
    std::copy(tests[i].in.begin(), tests[i].in.end(), rho_arr.begin());
    Rq c = SampleInBall<Params>(rho_arr);
    for (size_t j = 0; j < N; ++j) {
      EXPECT_EQ(c[j], Fq.of_scalar(tests[i].out[j]))
          << "Mismatch for test case t=" << i << " at j=" << j;
    }
  }
}

TYPED_TEST(MlDsaRefTest, SigDecode) {
  const Fp24& Fq = ml_dsa::Fq();
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  auto tests = Traits::GetSigDecodeTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    auto maybe_sig = sigDecode<Params>(tests[t].in);
    ASSERT_TRUE(maybe_sig.has_value());
    typename Traits::Signature sig = maybe_sig.value();

    // Verify c_tilde
    for (size_t i = 0; i < Params::c_tilde_bytes; ++i) {
      EXPECT_EQ(sig.c_tilde[i], tests[t].c_tilde[i])
          << "Mismatch c_tilde for test case t=" << t << " at i=" << i;
    }

    // Verify z
    for (size_t r = 0; r < Params::L; ++r) {
      for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(sig.z[r][i], Fq.of_scalar(tests[t].z[r][i]))
            << "Mismatch z for test case t=" << t << " at r=" << r
            << " i=" << i;
      }
    }

    // Verify h
    for (size_t r = 0; r < Params::K; ++r) {
      for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(sig.h[r][i], tests[t].h[r][i])
            << "Mismatch h for test case t=" << t << " at r=" << r
            << " i=" << i;
      }
    }
  }
}

TYPED_TEST(MlDsaRefTest, PkDecode) {
  const Fp24& Fq = ml_dsa::Fq();
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  auto tests = Traits::GetPkDecodeTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    typename Traits::PublicKey pub_key = pkDecode<Params>(tests[t].in);

    // Verify tr
    for (size_t i = 0; i < 64; ++i) {
      EXPECT_EQ(pub_key.tr[i], tests[t].tr[i])
          << "Mismatch tr for test case t=" << t << " at i=" << i;
    }

    // Verify t1
    for (size_t r = 0; r < Params::K; ++r) {
      for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(pub_key.t1[r][i], Fq.of_scalar(tests[t].t1[r][i]))
            << "Mismatch t1 for test case t=" << t << " at r=" << r
            << " i=" << i;
      }
    }

    typename Traits::MatrixA expected_A =
        ExpandA<Params>(std::vector<uint8_t>(tests[t].rho, tests[t].rho + 32));
    for (size_t r = 0; r < Params::K; ++r) {
      for (size_t s = 0; s < Params::L; ++s) {
        for (size_t i = 0; i < N; ++i) {
          EXPECT_EQ(pub_key.a_hat[r][s][i], expected_A[r][s][i])
              << "Mismatch a_hat at r=" << r << " s=" << s << " i=" << i;
        }
      }
    }
  }
}

TYPED_TEST(MlDsaRefTest, PreprocessMessage) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  for (const auto& ex : Traits::GetExamples()) {
    // 1. Get tr from pk
    typename Traits::PublicKey pub_key = pkDecode<Params>(ex.pkey);
    std::vector<uint8_t> tr(pub_key.tr.begin(), pub_key.tr.end());

    // 2. Preprocess Message
    auto maybe_m_prime = preprocess_message(ex.msg, ex.ctx);
    ASSERT_TRUE(maybe_m_prime.has_value());
    std::vector<uint8_t> m_prime = maybe_m_prime.value();

    // 3. Compute mu = H(tr || m_prime, 64)
    std::vector<uint8_t> input = tr;
    input.insert(input.end(), m_prime.begin(), m_prime.end());
    std::array<uint8_t, 64> mu;
    H(input, mu);

    EXPECT_TRUE((mu.size() == ex.mu.size()) &&
                std::equal(mu.begin(), mu.end(), ex.mu.begin()));
  }
}

TYPED_TEST(MlDsaRefTest, VerifyExamples) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  for (const auto& ex : Traits::GetExamples()) {
    EXPECT_TRUE(VerifySignature<Params>(ex.pkey, ex.sig, ex.msg, ex.ctx));
  }
}

TYPED_TEST(MlDsaRefTest, VerifyFailureExamples) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  for (const auto& ex : Traits::GetFailExamples()) {
    EXPECT_FALSE(VerifySignature<Params>(ex.pkey, ex.sig, ex.msg, ex.ctx));
  }
}

TYPED_TEST(MlDsaRefTest, UseHint) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  auto tests = Traits::GetUseHintTestCases();
  for (size_t i = 0; i < tests.size(); ++i) {
    bool h = tests[i].h;
    int32_t r = tests[i].r;
    uint32_t expected = tests[i].expected;
    uint32_t result = UseHint<Params>(h, r);
    EXPECT_EQ(result, expected)
        << "Mismatch for UseHint at index " << i << " h=" << h << " r=" << r;
  }
}

TYPED_TEST(MlDsaRefTest, W1Encode) {
  const Fp24& Fq = ml_dsa::Fq();
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  auto tests = Traits::GetW1EncodeTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    typename Traits::RqK w1;
    for (size_t r = 0; r < Params::K; ++r) {
      for (size_t i = 0; i < N; ++i) {
        w1[r][i] = Fq.of_scalar(tests[t].in[r][i]);
      }
    }

    auto encoded = w1Encode<Params>(w1);

    // Verify size
    EXPECT_EQ(encoded.size(), Params::K * Params::w1_bytes);

    for (size_t i = 0; i < encoded.size(); ++i) {
      EXPECT_EQ(encoded[i], tests[t].out[i])
          << "Mismatch at test " << t << " byte " << i;
    }
  }
}

TYPED_TEST(MlDsaRefTest, HintBitUnpackDuplicateZeroRejected) {
  using Params = typename TestFixture::Params;

  std::vector<uint8_t> y(Params::omega + Params::K, 0);
  // Set the first two hints to 0 (duplicate).
  y[0] = 0;
  y[1] = 0;
  // Set limits. Polynomial 0 has 2 hints (both are 0).
  // The rest of the polynomials have 0 hints.
  for (size_t i = 0; i < Params::K; ++i) {
    y[Params::omega + i] = 2;
  }

  // This should fail (return std::nullopt) because of the duplicate 0 hints.
  auto maybe_h = HintBitUnpack<Params>(y);
  EXPECT_FALSE(maybe_h.has_value());
}

TYPED_TEST(MlDsaRefTest, PreprocessMessageContextTooLongRejected) {
  using Params = typename TestFixture::Params;
  std::vector<uint8_t> msg = {1, 2, 3};
  std::vector<uint8_t> ctx(256, 0);  // 256 bytes context

  auto maybe_m_prime = preprocess_message(msg, ctx);
  EXPECT_FALSE(maybe_m_prime.has_value());
}

TYPED_TEST(MlDsaRefTest, VerifySignatureContextTooLongRejected) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;

  auto examples = Traits::GetExamples();
  if (examples.empty()) return;
  const auto& ex = examples[0];

  std::vector<uint8_t> ctx(256, 0);  // 256 bytes context

  // Should fail because context is too long.
  EXPECT_FALSE(VerifySignature<Params>(ex.pkey, ex.sig, ex.msg, ctx));
}

}  // namespace
}  // namespace ml_dsa
}  // namespace proofs

