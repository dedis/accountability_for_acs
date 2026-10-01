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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_65_EXAMPLES_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_65_EXAMPLES_H_

#include <cstdint>
#include <vector>

namespace proofs {
namespace ml_dsa_65 {

struct MlDsa65SignatureExample {
  std::vector<uint8_t> msg;
  std::vector<uint8_t> pkey;
  std::vector<uint8_t> ctx;
  std::vector<uint8_t> mu;
  std::vector<uint8_t> sig;
};

std::vector<MlDsa65SignatureExample> GetMlDsa65Examples();
std::vector<MlDsa65SignatureExample> GetMlDsa65FailExamples();

struct UseHintTestCase {
  bool h;
  int32_t r;
  uint32_t expected;
};

std::vector<UseHintTestCase> GetUseHintTestCases();

extern const uint64_t kExpectedExpandAVectors[6][5][256];

struct MlDsa65ByteInputOutput {
  std::vector<uint8_t> in;
  std::vector<uint32_t> out;
};
std::vector<MlDsa65ByteInputOutput> GetSampleInBallTests();

struct MlDsa65PkDecodeTest {
  std::vector<uint8_t> in;
  uint8_t rho[32];
  uint64_t t1[6][256];
  uint8_t tr[64];
};
std::vector<MlDsa65PkDecodeTest> GetPkDecodeTests();

struct MlDsa65SigDecodeTest {
  std::vector<uint8_t> in;
  uint8_t c_tilde[48];
  uint64_t z[5][256];
  bool h[6][256];
};
std::vector<MlDsa65SigDecodeTest> GetSigDecodeTests();

struct MlDsa65W1EncodeTests {
  int32_t in[6][256];
  std::vector<uint8_t> out;
};
std::vector<MlDsa65W1EncodeTests> GetW1EncodeTests();

}  // namespace ml_dsa_65
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_65_EXAMPLES_H_
