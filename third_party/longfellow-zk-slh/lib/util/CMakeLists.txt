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

add_library(util OBJECT log.cc crypto.cc)
target_link_libraries(util crypto zstd)

# util for the programs with 64-byte SHAKE256 digests (NIST category 5; not
# upstream). The definition reaches every program that links util64.
add_library(util64 OBJECT log.cc crypto.cc)
target_link_libraries(util64 crypto zstd)
target_compile_definitions(util64 PUBLIC PROOFS_SHAKE256_DIGEST_BYTES=64)


# SHAKE256 hash and PRF of the pq build (not upstream).
proofs_add_test(crypto_shake256_test)
target_compile_definitions(crypto_shake256_test PRIVATE PROOFS_SHAKE256)
