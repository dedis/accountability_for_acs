# SLH-DSA proofs over copies of one hash-step circuit (not upstream). The
# proof system uses SHAKE256 (util/crypto.h), as the pq build.
add_library(slh_dsa OBJECT slh_dsa_examples.cc)

proofs_add_test(zk_copies_test)
target_compile_definitions(zk_copies_test PRIVATE PROOFS_SHAKE256)

proofs_add_test(zk_soundness_test)
target_compile_definitions(zk_soundness_test PRIVATE PROOFS_SHAKE256)

proofs_add_test(ligero_prover_test)
target_compile_definitions(ligero_prover_test PRIVATE PROOFS_SHAKE256)

proofs_add_test(slh_dsa_test)
target_link_libraries(slh_dsa_test slh_dsa sha3)
target_compile_definitions(slh_dsa_test PRIVATE PROOFS_SHAKE256)

# The category 3 sets (48-byte digests) and the category 5 sets (64-byte
# digests) from the same source.
proofs_add_test(slh_dsa_zk_test)
proofs_add_test_digest64(slh_dsa_zk_5_test slh_dsa_zk_test.cc)
foreach(PROG slh_dsa_zk_test slh_dsa_zk_5_test)
  target_link_libraries(${PROG} slh_dsa sha3)
  target_compile_definitions(${PROG} PRIVATE PROOFS_SHAKE256)
endforeach()

proofs_add_test(extension_field_test)
target_compile_definitions(extension_field_test PRIVATE PROOFS_SHAKE256)
