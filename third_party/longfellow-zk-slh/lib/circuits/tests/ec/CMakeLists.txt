# Copyright 2026 Google LLC.
# EC test circuits and benchmarks (not used in production)

proofs_add_test(prove_verify_test prove_verify_shared.cc)
target_link_libraries(prove_verify_test flatsha)

proofs_add_test(prove_verify_no_cft_test prove_verify_no_cft_shared.cc)
target_link_libraries(prove_verify_no_cft_test flatsha)

proofs_add_test(attr_commitment_experiment_test attr_commitment_experiment_shared.cc)
target_link_libraries(attr_commitment_experiment_test flatsha)

proofs_add_test(prove_verify_revocation_test prove_verify_revocation_shared.cc)
target_link_libraries(prove_verify_revocation_test flatsha)

# Post-quantum variants (pq Cargo feature): the same benchmarks with SHAKE256 in
# place of SHA-256, in the circuits (PROOFS_EC_SHAKE256) and in the proof
# system (PROOFS_SHAKE256, util/crypto.h). Not upstream.
foreach(name prove_verify prove_verify_no_cft attr_commitment_experiment
             prove_verify_revocation)
  add_executable(${name}_pq_test ${name}_test.cc ${name}_shared.cc)
  target_compile_definitions(${name}_pq_test PRIVATE PROOFS_EC_SHAKE256
                                                     PROOFS_SHAKE256)
  target_link_libraries(${name}_pq_test ec algebra util sha3)
  proofs_add_testing_libraries(${name}_pq_test)
endforeach()
