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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_EXAMPLES_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_EXAMPLES_H_

#include <cstdint>
#include <vector>

namespace proofs {
namespace ml_dsa {

// This file defines test vectors for various steps of the ML-DSA-44
// verification algorithm.  Because these objects are cumbersome, many
// are defined in .inc files and included in the corresponding .cc file.
// This header file defines the structures used to hold these test vectors.

struct MlDsa44SignatureExample {
  std::vector<uint8_t> msg;
  std::vector<uint8_t> pkey;
  std::vector<uint8_t> ctx;
  std::vector<uint8_t> mu;
  std::vector<uint8_t> sig;
};

std::vector<MlDsa44SignatureExample> GetMlDsa44Examples();

std::vector<MlDsa44SignatureExample> GetMlDsa44FailExamples();

struct UseHintTestCase {
  bool h;
  int32_t r;
  uint32_t expected;
};

std::vector<UseHintTestCase> GetUseHintTestCases();

extern const uint64_t kExpectedExpandAVectors[4][4][256];

struct MlDsa44ByteInputOutput {
  std::vector<uint8_t> in;
  std::vector<uint32_t> out;
};

std::vector<MlDsa44ByteInputOutput> GetSampleInBallTests();

struct MlDsa44PkDecodeTest {
  std::vector<uint8_t> in;
  uint8_t rho[32];
  uint64_t t1[4][256];
  uint8_t tr[64];
};

std::vector<MlDsa44PkDecodeTest> GetPkDecodeTests();

struct MlDsa44SigDecodeTest {
  std::vector<uint8_t> in;
  uint8_t c_tilde[32];
  uint64_t z[4][256];
  bool h[4][256];
};

std::vector<MlDsa44SigDecodeTest> GetSigDecodeTests();

struct MlDsa44W1EncodeTests {
  int32_t in[4][256];
  std::vector<uint8_t> out;
};

std::vector<MlDsa44W1EncodeTests> GetW1EncodeTests();

struct MlDsa44NTTTest {
  std::vector<uint32_t> in;
  std::vector<uint32_t> out;
};

std::vector<MlDsa44NTTTest> GetNTTTests();

}  // namespace ml_dsa
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_44_EXAMPLES_H_
