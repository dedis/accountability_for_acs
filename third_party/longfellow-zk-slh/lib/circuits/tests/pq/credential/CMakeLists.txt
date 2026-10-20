# Post-quantum credential proofs over several circuits with copies (not
# upstream). The proof system uses SHAKE256 (util/crypto.h), as the pq
# build.

proofs_add_test(zk_multi_test)
target_link_libraries(zk_multi_test ml_dsa sha3)
target_compile_definitions(zk_multi_test PRIVATE PROOFS_SHAKE256)

proofs_add_test(sponge_test)
target_link_libraries(sponge_test ml_dsa sha3)
target_compile_definitions(sponge_test PRIVATE PROOFS_SHAKE256)

# The credential proofs, with ML-DSA-65 (48-byte digests) and ML-DSA-87
# (64-byte digests, util64), from the same source. Signing uses OpenSSL 3.5
# or newer (ML-DSA, SLH-DSA).
proofs_add_test(pq_credential_test)
proofs_add_test_digest64(pq_credential_5_test pq_credential_test.cc)
foreach(PROG pq_credential_test pq_credential_5_test)
  target_link_libraries(${PROG} ml_dsa sha3 crypto)
  target_compile_definitions(${PROG} PRIVATE PROOFS_SHAKE256)
endforeach()

proofs_add_test(checkpoint_test)
target_link_libraries(checkpoint_test ml_dsa sha3)
target_compile_definitions(checkpoint_test PRIVATE PROOFS_SHAKE256)

proofs_add_test(circuit_cache_test)
target_link_libraries(circuit_cache_test ml_dsa sha3)
target_compile_definitions(circuit_cache_test PRIVATE PROOFS_SHAKE256)

# Warnings are errors. -Wunused-parameter is off: upstream headers
# (algebra, gf2k, logic, sumcheck, ligero) have unused parameters.
foreach(PROG zk_multi_test sponge_test checkpoint_test circuit_cache_test
             pq_credential_test pq_credential_5_test)
  target_compile_options(${PROG} PRIVATE -Wall -Wextra -Werror
                                         -Wno-unused-parameter)
endforeach()
