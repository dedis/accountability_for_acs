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

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "algebra/fp24.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_65_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_circuit.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_witness.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = Fp24;
using EvalBackend = EvaluationBackend<Field>;
using EvalLogic = Logic<Field, EvalBackend>;

template <typename Params>
using Verify = MLDSAVerify<EvalLogic, Field, Params>;

using v8 = typename EvalLogic::v8;

Sha3Circuit<EvalLogic>::BlockWitness convert_block_witness(
    const EvalLogic& L, const Sha3Witness::BlockWitness& raw_bw) {
  Sha3Circuit<EvalLogic>::BlockWitness bw;
  for (size_t round = 0; round < 24; ++round) {
    for (size_t x = 0; x < 5; ++x) {
      for (size_t y = 0; y < 5; ++y) {
        bw.a_intermediate[round][x][y] =
            L.template vbit<64>(raw_bw.a_intermediate[round][x][y]);
      }
    }
  }
  return bw;
}

template <typename Params, typename Container>
void convert_rqw(typename MLDSAVerify<EvalLogic, Field, Params>::RqW& dst,
                 const Container& src, const EvalLogic& L) {
  for (size_t i = 0; i < ml_dsa::N; ++i) {
    dst.coeffs[i] = L.konst(src[i]);
  }
}

void push_bytes(std::vector<v8>& dst, const uint8_t* src, size_t size,
                const EvalLogic& L) {
  for (size_t i = 0; i < size; ++i) {
    dst.push_back(L.vbit8(src[i]));
  }
}

template <typename SrcContainer, typename DstContainer>
void convert_array(DstContainer& dst, const SrcContainer& src,
                   const EvalLogic& L) {
  for (size_t i = 0; i < src.size(); ++i) {
    dst[i] = L.vbit8(src[i]);
  }
}

template <size_t N_bits, typename SrcContainer, typename DstContainer>
void convert_array_bits(DstContainer& dst, const SrcContainer& src,
                        const EvalLogic& L) {
  for (size_t i = 0; i < src.size(); ++i) {
    dst[i] = L.template vbit<N_bits>(src[i]);
  }
}

template <typename Params>
typename MLDSAVerify<EvalLogic, Field, Params>::Pk convert_pk(
    const typename ml_dsa::MLDsaTypes<Params>::PublicKey& ref_pk,
    const ml_dsa_witness<Params>& witness_gen, const EvalLogic& L,
    const Field& F) {
  typename MLDSAVerify<EvalLogic, Field, Params>::Pk pk_w;
  for (size_t r = 0; r < Params::K; ++r) {
    for (size_t s = 0; s < Params::L; ++s) {
      convert_rqw<Params>(pk_w.a_hat.mat[r][s], ref_pk.a_hat[r][s], L);
    }
  }
  for (size_t r = 0; r < Params::K; ++r) {
    convert_rqw<Params>(pk_w.nttt1[r], witness_gen.nttt1_[r], L);
  }
  convert_array(pk_w.tr, witness_gen.tr_, L);
  return pk_w;
}

template <typename Params>
typename MLDSAVerify<EvalLogic, Field, Params>::SignatureW convert_sig(
    const typename ml_dsa::MLDsaTypes<Params>::Signature& ref_sig,
    const ml_dsa_witness<Params>& witness_gen, const EvalLogic& L,
    const Field& F) {
  typename MLDSAVerify<EvalLogic, Field, Params>::SignatureW sig_w;
  convert_array(sig_w.c_tilde, witness_gen.c_tilde_, L);
  for (size_t r = 0; r < Params::L; ++r) {
    convert_rqw<Params>(sig_w.z[r], ref_sig.z[r], L);
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      sig_w.z_bits[r][i] =
          L.template vbit<Params::z_bits>(witness_gen.z_bits_[r][i]);
    }
  }
  for (size_t r = 0; r < Params::K; ++r) {
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      sig_w.h[r].coeffs[i] = L.konst(ref_sig.h[r][i] ? F.one() : F.zero());
    }
  }
  return sig_w;
}

template <typename Params>
typename MLDSAVerify<EvalLogic, Field, Params>::SampleInBallWitness
convert_sample_in_ball(const ml_dsa_witness<Params>& witness_gen,
                       const EvalLogic& L, const Field& F) {
  typename MLDSAVerify<EvalLogic, Field, Params>::SampleInBallWitness sib_w;
  sib_w.shake_bws = convert_block_witness(L, witness_gen.shake_bws_);
  for (size_t i = 0; i < Params::tau; ++i) {
    sib_w.j_vals[i] = L.vbit8(witness_gen.j_vals_[i]);
    sib_w.j_k_indices[i] = L.template vbit<16>(witness_gen.j_k_indices_[i]);
  }
  sib_w.position_trace.resize(witness_gen.position_trace_.size());
  for (size_t s = 0; s < witness_gen.position_trace_.size(); ++s) {
    sib_w.position_trace[s].resize(witness_gen.position_trace_[s].size());
    convert_array(sib_w.position_trace[s], witness_gen.position_trace_[s], L);
  }
  return sib_w;
}

template <typename Params>
typename MLDSAVerify<EvalLogic, Field, Params>::Witness convert_witness(
    const ml_dsa_witness<Params>& witness_gen, const EvalLogic& L,
    const Field& F) {
  typename MLDSAVerify<EvalLogic, Field, Params>::Witness witness;
  convert_rqw<Params>(witness.c_, witness_gen.c_coeffs_, L);

  witness.sample_in_ball_ = convert_sample_in_ball<Params>(witness_gen, L, F);

  for (size_t i = 0; i < Params::L; ++i) {
    convert_rqw<Params>(witness.nttz_[i], witness_gen.nttz_[i], L);
  }
  convert_rqw<Params>(witness.nttc_, witness_gen.nttc_, L);
  for (size_t i = 0; i < Params::K; ++i) {
    convert_rqw<Params>(witness.w_prime_approx_[i],
                        witness_gen.w_prime_approx_[i], L);
  }

  for (size_t i = 0; i < Params::K; ++i) {
    for (size_t k = 0; k < ml_dsa::N; ++k) {
      int32_t w1_val = witness_gen.w1_[i][k];
      if (w1_val < 0) {
        w1_val += ml_dsa::Q;
      }
      witness.w1_[i].coeffs[k] = L.konst(L.f_.of_scalar(w1_val));
      witness.hint_aux_bits_[i][k] = L.template vbit<Params::r0_bits + 1>(
          witness_gen.hint_aux_bits_[i][k]);
      witness.w1_bits_[i][k] =
          L.template vbit<Params::r1_bits>(witness_gen.w1_bits_[i][k]);
    }
  }

  for (size_t i = 0; i < Params::K; ++i) {
    for (size_t k = 0; k < ml_dsa::N; ++k) {
      int32_t w1_val = witness_gen.w_prime_1_[i][k];
      EXPECT_TRUE(w1_val >= 0 && w1_val <= (Params::M - 1));
    }
    convert_rqw<Params>(witness.w_prime_1_[i], witness_gen.w_prime_1_[i], L);
    convert_array_bits<Params::r1_bits>(witness.w_prime_1_bits_[i],
                                        witness_gen.w_prime_1_bits_[i], L);
  }

  convert_array(witness.w1_tilde_, witness_gen.w1_tilde_, L);

  for (const auto& raw_bw : witness_gen.c_prime_tilde_bws_) {
    witness.c_prime_tilde_bws_.push_back(convert_block_witness(L, raw_bw));
  }

  witness.h_sum_bits_ =
      L.template vbit<MLDSAVerify<EvalLogic, Field, Params>::kOmegaBits>(
          witness_gen.h_sum_bits_);

  return witness;
}

template <typename Params>
struct MLDsaEvalTestTraits;

template <>
struct MLDsaEvalTestTraits<ml_dsa::MLDsa44Params> {
  using Params = ml_dsa::MLDsa44Params;
  using Verify = MLDSAVerify<EvalLogic, Field, Params>;
  using SignatureExample = ml_dsa::MlDsa44SignatureExample;
  using ByteInputOutput = ml_dsa::MlDsa44ByteInputOutput;

  static std::vector<SignatureExample> GetExamples() {
    return ml_dsa::GetMlDsa44Examples();
  }
  static std::vector<ByteInputOutput> GetSampleInBallTests() {
    return ml_dsa::GetSampleInBallTests();
  }
  static std::vector<ml_dsa::UseHintTestCase> GetUseHintTestCases() {
    return ml_dsa::GetUseHintTestCases();
  }
  static std::vector<ml_dsa::MlDsa44W1EncodeTests> GetW1EncodeTests() {
    return ml_dsa::GetW1EncodeTests();
  }
};

template <>
struct MLDsaEvalTestTraits<ml_dsa::MLDsa65Params> {
  using Params = ml_dsa::MLDsa65Params;
  using Verify = MLDSAVerify<EvalLogic, Field, Params>;
  using SignatureExample = ml_dsa_65::MlDsa65SignatureExample;
  using ByteInputOutput = ml_dsa_65::MlDsa65ByteInputOutput;

  static std::vector<SignatureExample> GetExamples() {
    return ml_dsa_65::GetMlDsa65Examples();
  }
  static std::vector<ByteInputOutput> GetSampleInBallTests() {
    return ml_dsa_65::GetSampleInBallTests();
  }
  static std::vector<ml_dsa_65::UseHintTestCase> GetUseHintTestCases() {
    return ml_dsa_65::GetUseHintTestCases();
  }
  static std::vector<ml_dsa_65::MlDsa65W1EncodeTests> GetW1EncodeTests() {
    return ml_dsa_65::GetW1EncodeTests();
  }
};

template <typename T>
class MlDsaEvalTest : public ::testing::Test {
 public:
  using Params = T;
  using Traits = MLDsaEvalTestTraits<Params>;
};

using MLDsaEvalTestTypes =
    ::testing::Types<ml_dsa::MLDsa44Params, ml_dsa::MLDsa65Params>;
TYPED_TEST_SUITE(MlDsaEvalTest, MLDsaEvalTestTypes);

TYPED_TEST(MlDsaEvalTest, SampleInBall) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;
  using Verify = typename Traits::Verify;

  const Field& F = ml_dsa::Fq();
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  Verify verify(L);

  auto tests = Traits::GetSampleInBallTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    std::vector<uint8_t> rho(Params::c_tilde_bytes);
    std::array<EvalLogic::v8, Params::c_tilde_bytes> rho_w_arr;
    for (size_t i = 0; i < Params::c_tilde_bytes; ++i) {
      rho[i] = tests[t].in[i];
      rho_w_arr[i] = L.vbit8(rho[i]);
    }

    std::array<uint8_t, 136> out;
    ml_dsa::H(rho, out);

    typename Verify::SampleInBallWitness witness;

    size_t out_idx = 8;
    witness.position_trace.resize(Params::tau);
    std::vector<uint8_t> current_pos;
    current_pos.reserve(Params::tau);

    for (size_t s = 0; s < Params::tau; ++s) {
      size_t i = 256 - Params::tau + s;
      uint8_t j;
      do {
        j = out[out_idx++];
      } while (j > i);
      witness.j_vals[s] = L.vbit8(j);
      witness.j_k_indices[s] = L.template vbit<16>(out_idx - 1);

      for (size_t k = 0; k < current_pos.size(); ++k) {
        if (current_pos[k] == j) {
          current_pos[k] = i;
          break;
        }
      }
      current_pos.push_back(j);

      witness.position_trace[s].reserve(s + 1);
      for (auto p : current_pos) {
        witness.position_trace[s].push_back(L.vbit8(p));
      }
    }

    std::vector<Sha3Witness::BlockWitness> bws;
    Sha3Witness::compute_witness_shake256(rho, 136, bws);
    witness.shake_bws = convert_block_witness(L, bws[0]);

    typename Verify::RqW cprime;
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      cprime.coeffs[i] = L.konst(F.of_scalar(tests[t].out[i]));
    }

    verify.assert_sample_in_ball(rho_w_arr, cprime, witness);
  }
}

TYPED_TEST(MlDsaEvalTest, UseHintSingle) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;
  using Verify = typename Traits::Verify;

  const Field& F = ml_dsa::Fq();
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  Verify verify(L);

  auto tests = Traits::GetUseHintTestCases();
  for (const auto& test_case : tests) {
    bool h = test_case.h;
    int32_t r = test_case.r;
    int32_t expected = test_case.expected;

    auto [r1, r0] = ml_dsa::Decompose<Params>(r);

    int32_t w1_raw = r1;
    if (h && r0 > 0)
      w1_raw = r1 + 1;
    else if (h && r0 <= 0)
      w1_raw = r1 - 1;

    int64_t gamma2 = static_cast<int64_t>(Params::gamma_2);
    int64_t delta =
        static_cast<int64_t>(r) - static_cast<int64_t>(r1) * (2 * gamma2);

    delta = delta % static_cast<int64_t>(ml_dsa::Q);
    if (delta > static_cast<int64_t>(ml_dsa::Q) / 2) {
      delta -= ml_dsa::Q;
    } else if (delta < -static_cast<int64_t>(ml_dsa::Q) / 2) {
      delta += ml_dsa::Q;
    }

    uint64_t R = delta + gamma2;
    uint64_t s = (delta > 0) ? 0 : 1;
    uint64_t aux_bits = R | (s << Params::r0_bits);

    auto normalize = [](int64_t x) {
      int64_t v = x % static_cast<int64_t>(ml_dsa::Q);
      if (v < 0) v += ml_dsa::Q;
      return static_cast<uint64_t>(v);
    };

    auto h_elt = L.konst(F.of_scalar(normalize(h)));
    auto w_prime_approx_elt = L.konst(F.of_scalar(normalize(r)));
    auto w1_elt = L.konst(F.of_scalar(normalize(r1)));
    auto w_prime_1_elt = L.konst(F.of_scalar(normalize(expected)));

    auto hint_aux_bits =
        L.template vbit<Params::r0_bits + 1>(normalize(aux_bits));
    auto w_prime_1_bits = L.template vbit<Params::r1_bits>(normalize(expected));
    auto w1_bits = L.template vbit<Params::r1_bits>(normalize(r1));

    verify.assert_use_hint_single(h_elt, w_prime_approx_elt, w1_elt, w1_bits,
                                  hint_aux_bits, w_prime_1_elt, w_prime_1_bits);
  }
}

TYPED_TEST(MlDsaEvalTest, W1Encode) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;
  using Verify = typename Traits::Verify;

  const Field& F = ml_dsa::Fq();
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  Verify verify(L);

  auto tests = Traits::GetW1EncodeTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    std::array<std::array<typename EvalLogic::template bitvec<Params::r1_bits>,
                          ml_dsa::N>,
               Params::K>
        w_prime_1_bits_arr;
    for (size_t k = 0; k < Params::K; ++k) {
      for (size_t i = 0; i < ml_dsa::N; ++i) {
        w_prime_1_bits_arr[k][i] =
            L.template vbit<Params::r1_bits>(tests[t].in[k][i]);
      }
    }

    std::array<EvalLogic::v8, Params::K * Params::w1_bytes> putative_out;
    for (size_t i = 0; i < tests[t].out.size(); ++i) {
      putative_out[i] = L.vbit8(tests[t].out[i]);
    }
    verify.assert_w1_encode(w_prime_1_bits_arr, putative_out);
  }
}

TYPED_TEST(MlDsaEvalTest, AssertValidSignature) {
  using Params = typename TestFixture::Params;
  using Traits = typename TestFixture::Traits;
  using Verify = typename Traits::Verify;
  using WitnessGen = ml_dsa_witness<Params>;

  const Field& F = ml_dsa::Fq();
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  Verify verify(L);

  auto tests = Traits::GetExamples();
  for (size_t t = 0; t < tests.size(); ++t) {
    const auto& example = tests[t];

    typename ml_dsa::MLDsaTypes<Params>::PublicKey ref_pk =
        ml_dsa::pkDecode<Params>(example.pkey);
    auto maybe_ref_sig = ml_dsa::sigDecode<Params>(example.sig);
    EXPECT_TRUE(maybe_ref_sig.has_value());
    typename ml_dsa::MLDsaTypes<Params>::Signature ref_sig =
        maybe_ref_sig.value();

    WitnessGen witness_gen;
    witness_gen.compute_witness(example.pkey, example.sig, example.msg,
                                example.ctx);

    typename Verify::Pk pk_w = convert_pk<Params>(ref_pk, witness_gen, L, F);

    typename Verify::SignatureW sig_w =
        convert_sig<Params>(ref_sig, witness_gen, L, F);

    typename Verify::Witness witness =
        convert_witness<Params>(witness_gen, L, F);

    std::array<EvalLogic::v8, 64> mu;
    convert_array(mu, witness_gen.mu_, L);
    verify.assert_valid_signature_on_mu(pk_w, sig_w, mu, witness);
  }
}

TEST(MlDsaEvalSharedTest, SHA3_Consistency) {
  const Field& F = ml_dsa::Fq();
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  Sha3Circuit<EvalLogic> sha3(L);

  std::vector<uint8_t> rho(32);
  for (int i = 0; i < 32; ++i) rho[i] = i;

  std::array<uint8_t, 272> expected_out;
  ml_dsa::H(rho, expected_out);

  std::vector<Sha3Witness::BlockWitness> bws;
  Sha3Witness::compute_witness_shake256(rho, 272, bws);

  std::vector<Sha3Circuit<EvalLogic>::BlockWitness> circuit_bws(bws.size());
  for (size_t k = 0; k < bws.size(); ++k) {
    circuit_bws[k] = convert_block_witness(L, bws[k]);
  }

  std::vector<EvalLogic::v8> rho_vec;
  push_bytes(rho_vec, rho.data(), rho.size(), L);

  std::vector<EvalLogic::v8> out;
  sha3.assert_shake256(rho_vec, 272, out, circuit_bws);

  ASSERT_EQ(out.size(), expected_out.size());
  for (size_t i = 0; i < out.size(); ++i) {
    uint8_t val = 0;
    for (int b = 0; b < 8; ++b) {
      if (L.eval(out[i][b]).elt() == F.one()) {
        val |= (1 << b);
      }
    }
    EXPECT_EQ(val, expected_out[i]);
  }
}

TEST(MlDsaEvalSharedTest, NTTConsistency) {
  const Field& F = ml_dsa::Fq();
  const EvalBackend ebk(F);
  const EvalLogic L(&ebk, F);
  MLDSAVerify<EvalLogic, Field, ml_dsa::MLDsa44Params> verify(L);

  auto tests = ml_dsa::GetNTTTests();
  for (size_t t = 0; t < tests.size(); ++t) {
    decltype(verify)::RqW w_in, w_out;
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      w_in.coeffs[i] = L.konst(F.of_scalar(tests[t].in[i]));
      w_out.coeffs[i] = L.konst(F.of_scalar(tests[t].out[i]));
    }
    verify.assert_ntt(w_in, w_out);
  }

  for (size_t t = 0; t < tests.size(); ++t) {
    decltype(verify)::RqW w_in, w_out;
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      w_in.coeffs[i] = L.konst(F.of_scalar(tests[t].out[i]));
      w_out.coeffs[i] = L.konst(F.of_scalar(tests[t].in[i]));
    }
    verify.assert_inverse_ntt(w_in, w_out);
  }
}

}  // namespace
}  // namespace proofs
