# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_library(sha3 OBJECT sha3_reference.cc sha3_round_constants.cc
sha3_witness.cc)

proofs_add_tests(sha3_circuit_test sha3_reference_test)
target_link_libraries(sha3_circuit_test sha3)
target_link_libraries(sha3_reference_test sha3)

# SHAKE256 counterpart of BM_ShaZK_fp2_128 (not upstream).
proofs_add_tests(shake256_zk_test)
target_link_libraries(shake256_zk_test sha3)
