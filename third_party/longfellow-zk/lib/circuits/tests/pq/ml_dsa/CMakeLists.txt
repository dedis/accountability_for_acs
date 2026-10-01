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

add_library(ml_dsa OBJECT ml_dsa_shared.cc ml_dsa_44_examples.cc ml_dsa_65_examples.cc
 ml_dsa_ref.cc )

proofs_add_test(ml_dsa_circuit_test)
target_link_libraries(ml_dsa_circuit_test ml_dsa sha3)

proofs_add_test(ml_dsa_44_witness_test)
target_link_libraries(ml_dsa_44_witness_test ml_dsa sha3)

proofs_add_test(ml_dsa_eval_test)
target_link_libraries(ml_dsa_eval_test ml_dsa sha3)

proofs_add_test(ml_dsa_ref_test)
target_link_libraries(ml_dsa_ref_test ml_dsa sha3)


# ML-DSA-65 Combined prove/verify benchmark (not upstream).
proofs_add_test(ml_dsa_65_zk_test)
target_link_libraries(ml_dsa_65_zk_test ml_dsa sha3)
