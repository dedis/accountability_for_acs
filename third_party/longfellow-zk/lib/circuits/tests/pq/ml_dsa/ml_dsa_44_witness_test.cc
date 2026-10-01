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

#include "circuits/tests/pq/ml_dsa/ml_dsa_44_witness.h"

#include <cstdint>

#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

TEST(MlDsa44WitnessTest, SymmetricReduce) {
  // Case 1: delta < Q/2, positive
  EXPECT_EQ(ml_dsa_44_witness::SymmetricReduce(100), 100);

  // Case 2: delta = 0
  EXPECT_EQ(ml_dsa_44_witness::SymmetricReduce(0), 0);

  // Case 3: delta > Q/2 (e.g. Q-1)
  // This triggers the delta -= Q branch
  int64_t q = static_cast<int64_t>(ml_dsa::Q);
  EXPECT_EQ(ml_dsa_44_witness::SymmetricReduce(q - 1), -1);

  // Case 4: delta near Q/2
  EXPECT_EQ(ml_dsa_44_witness::SymmetricReduce(q / 2), q / 2);
  EXPECT_EQ(ml_dsa_44_witness::SymmetricReduce(q / 2 + 1), q / 2 + 1 - q);

  // Case 5: delta is negative but > -Q/2
  EXPECT_EQ(ml_dsa_44_witness::SymmetricReduce(-100), -100);

  // Case 6: delta is exactly -Q/2
  EXPECT_EQ(ml_dsa_44_witness::SymmetricReduce(-q / 2), -q / 2);
}

}  // namespace
}  // namespace proofs
