# SLH-DSA proofs (not upstream)

Experimental research code: do not use in production.

Zero-knowledge proofs of SLH-DSA verification (FIPS 205, SHAKE parameter
sets 192s, 192f, 256s, 256f). Statement: a valid signature on a private
message of public length, under a public key and a public context.

## Design

SLH-DSA verification is 5,748 (192s) to 17,803 (256f) Keccak-f calls. The
Longfellow circuit compiler needs about 160 MB per Keccak-f call, so one
circuit for all calls cannot be compiled. Instead:

- `slh_dsa_circuit.h`: one hash-step circuit, compiled once. A step absorbs
  one 136-byte block and proves Keccak-f; for a later block of a call it
  takes the previous capacity (512 bits) as input, and its block is linked
  to the previous output XOR the data.
  It can exchange the two n-byte windows of the block (Merkle left/right),
  pass its input through (WOTS+ chain positions below the digit), and add a
  digit to the WOTS+ checksum.
- `slh_dsa.h` (`Plan`): walks `slh_verify` and gives each Keccak-f call one
  copy of the step circuit. Per copy it records the public inputs (constant
  bits of the block, which bits are private, flags), the witness, and the
  links: private bit = private bit of another copy (hash outputs, digest
  bits, indices, chained capacity), private bit = constant (PK.root, a zero
  checksum), or private bit = previous output bit XOR a data bit or constant
  (later blocks; XOR is addition in GF(2^128), so the link is linear). The copies, public inputs and links depend only on the
  parameter set, the public key, the context and the message length.
- `slh_dsa_zk.h`: proves all copies at once (sumcheck over copies) and
  checks the links as linear constraints on the committed witness.
  `SlhDsaZk::Make` returns nullptr for a key or context of a wrong length
  or a message longer than `kMaxMessageBytes` (64 KiB, a limit on memory
  and time, not from FIPS 205); `Prove` returns false for a message or
  signature of a wrong length, as `Plan` does (FIPS 205 Alg. 24).
- Proof soundness per NIST category (`SlhDsaZk<P, Z>`): `ZkCategory3`
  (GF(2^256), 281 Ligero queries at rate 4, 48-byte digests) gives 192.1
  bits for 192s and 192f; `ZkCategory5` (GF(2^384), 374 queries, 64-byte
  digests) gives 256.4 bits for 256s and 256f. The digest size is fixed per
  program, so `slh_dsa_zk_test` proves the category 3 sets and
  `slh_dsa_zk_5_test` (same source, linked with `util64`) the category 5
  sets. `zk/zk_soundness.h` computes the bits (sumcheck union bound; Ligero
  code, linear and quadratic tests in the unique-decoding regime) and
  `SlhDsaZk.Soundness` checks them.
- Every input of the step circuit is a bit, so the circuit marks all inputs
  as subfield (GF(2^16)) elements (`begin_full_field` after the inputs): the
  witness rows of the Ligero tableau take subfield randomness, and their
  opened elements are sent in 2 bytes instead of 32 or 48. `Verify` checks
  the proof after serializing and parsing it.
- One-block copies (`Plan` with `one_block`, `Layout1`,
  `OneBlockStepCircuit`; used by the credential proofs, `../credential`): a
  call of one block whose output is read only through R (F and H, more than
  98% of the copies) has a zero capacity input and no committed output
  state, and
  only its first W = 3n + 32 block bytes can be private: 1,053 (n = 24) or
  1,309 (n = 32) private inputs instead of 3,421 or 3,485. The relation is
  that of the step circuit. `SlhDsaZk` keeps one circuit for all copies.

Changes to this copy of Longfellow outside this directory:

| File | Change |
|---|---|
| `zk/zk_common.h` | ZK constraints for circuits with copies: sumcheck rounds over the copy variables, the input binding over all copies, `EQ` on the copy bindings of the previous layer; extra linear constraints from the statement (`ExtraConstraints`), with index checks and a hash of all terms and right-hand sides for the transcript; `num_terms`, the exact size of the constraint list; `witness_index` rejects an input or copy out of range; `replay_sumcheck`, the transcript steps of the sumcheck without the constraints |
| `zk/zk_prover.h`, `zk/zk_verifier.h` | Witness of all copies, extra constraints; the prover option `low_memory`, set by `SlhDsaZk` (the sumcheck on packed layers with a checkpoint every sqrt(layers) layers, `prove_low_memory`, and the Ligero witness rows encoded again; off: the upstream sumcheck on dense layers, all kept, and the encoded rows kept); the prover takes packed inputs (`commit` and `prove` on a `PackedLayer`; the `Dense` versions pack and forward) and reads the witness and the public inputs from them in place; the verifier takes `Dense` or packed public inputs; `prove` consumes the commitment (one proof per commit, so the pads are never used twice); the constraint list is allocated once, at its final size; the verifier checks the Merkle openings before it builds the constraint list |
| `arrays/packed_layer.h` | `PackedLayer`: the wires of all copies, with each 0/1 wire as one bit per copy; filled per wire or per bit, read in the layout of `Dense` |
| `sumcheck/prover_layers.h` | `prove_low_memory` (on packed inputs, which the caller keeps): every layer is stored as a `PackedLayer`, with each wire that is 0 or 1 in every copy as one bit per copy. `eval_layer` evaluates a layer from its packed input by output wire (terms counting-sorted by output wire) and packs each output wire at once, so no layer is ever unpacked at full size. `layer_packed` computes the first copy round from the packed wires (for two bit wires, the product of a pair of copies depends on four bits: the round adds `EQ` into 16 classes and multiplies once per class), then (credential work, `../credential/README.md`) the second round from the packed wires too, and binds both into a buffer of a quarter of the copies, which holds the layer for the other rounds. Same proof. Evaluation selects (does not multiply by) a bit factor and does not multiply by a coefficient of one; same values. Packing, unpacking and evaluation do the same work and branches for every value of the bits, so the time depends only on the circuit (the first copy round indexes a 16-entry table, in L1, by the bits). One buffer for the sumcheck rounds of a layer |
| `zk/zk_proof.h` | Serialization of the copy rounds; one encoding per proof: no trailing bytes, only the writer's run chunking, runs below the reader's limit |
| `merkle/merkle_tree.h` | A compressed Merkle proof must not hold unused digests |
| `ligero/ligero_prover.h` | Each witness row keeps its input (random elements, and witnesses packed as bits when all are 0/1); with `low_memory` (set by `SlhDsaZk` and `zk_multi.h`), the encoded witness rows are not kept and a row is encoded again when needed, else they are kept as upstream; the columns are hashed row by row (one hash state per column). The blinding and quadratic rows stay encoded. Each buffer is allocated once; every commit starts from a clear state. Packing does not branch on the bit values. Same proof |
| `ligero/ligero_verifier.h` | `check_openings`: the Merkle check alone, with the challenges of `verify` |
| `merkle/merkle_commitment.h` | `draw_nonces` and `commit_leaves`, for leaves hashed by the caller |
| `ligero/ligero_param.h` | Tableau limit 2^32 elements (upstream 2^28); 64-bit only; a clear error when no tableau fits; `LigeroProductRow`, a constraint row whose coefficients are U[i] V[j], given to the prover and verifier in place of U.size() V.size() terms (the input binding of all copies: 62 M terms for 256f) |
| `circuits/tests/sha3/sha3_slicing.h` | The period `PROOFS_SHA3_SLICE_PERIOD`: 24 in this directory and `../credential` (Keccak-f witness at round 23 only), 6 (upstream) elsewhere |
| `gf2k/gf2_128_ext.h` | GF(2^256) and GF(2^384) as extensions of GF(2^128) of degree 2 (y^2 = y + x^121) and 3 (y^3 = x), with the GF(2^16) subfield of GF(2^128); Karatsuba multiplication (3 or 6 base products) |
| `algebra/fp24_ext.h` | Extensions of Fp24 of any degree K (x^K - beta, checked irreducible); ML-DSA uses K = 12 |
| `algebra/reed_solomon_componentwise.h` | Reed-Solomon over an extension field, coordinate by coordinate with the base-field code |
| `zk/zk_soundness.h` | Soundness bits of a proof from its circuit and Ligero parameters |
| `util/crypto.h` | `PROOFS_SHAKE256_DIGEST_BYTES`: 48-byte digests by default, 64 for category 5 |
| `util/CMakeLists.txt`, `CMake/proofs.cmake` | `util64` (util with 64-byte digests) and `proofs_add_test_digest64`, for the category 5 programs |

Tests of the copy support:

- `zk_copies_test.cc`: proofs for 1 to 13 copies; rejection of a changed
  public input, a broken link, another or malformed constraint list, a
  changed copy-round polynomial, a witness that differs from the commitment,
  and non-canonical proof encodings.
- `ligero_prover_test.cc` (with `reference_ligero_prover.h`, the upstream
  prover): the Ligero prover gives the upstream commitment and proof byte for
  byte, for witnesses of bits, of random elements and mixed, over GF(2^128)
  and a prime field.
- `extension_field_test.cc`: GF(2^256) and GF(2^384) satisfy the field
  axioms and their modulus; serialization and the subfield; the
  coordinate-wise Reed-Solomon code equals LCH14 over the extension.
- `zk_soundness_test.cc` (with `malicious_*.h`, copies of the prover with
  attack hooks): a malicious prover that skips its checks and changes proof
  elements before Fiat-Shamir. False copies, every changed sumcheck element,
  junk in the padding copies of a non-power-of-two copy count, and a changed
  right-hand side of the extra constraints are rejected, over GF(2^128) and
  a prime field.

Four review agents (two soundness pentests, one transcript and parsing
pentest, one verification against upstream) found no soundness break; the
fixes above address their low-severity findings.

## Build and run

```bash
cmake -S third_party/longfellow-zk/lib -B .work/standard/longfellow-build \
  -DCMAKE_BUILD_TYPE=Release
cmake --build .work/standard/longfellow-build -j 8 \
  --target zk_copies_test zk_soundness_test ligero_prover_test extension_field_test \
  slh_dsa_test slh_dsa_zk_test slh_dsa_zk_5_test
B=.work/standard/longfellow-build/circuits/tests/pq/slh_dsa
$B/zk_copies_test && $B/zk_soundness_test && $B/ligero_prover_test && \
  $B/extension_field_test && $B/slh_dsa_test  # fast
$B/slh_dsa_zk_test --gtest_filter=SlhDsaZk.*                 # 192s proof
$B/slh_dsa_zk_5_test --benchmark_filter=SLHDSA_SHAKE_256s --benchmark_min_time=1x
```

`slh_dsa_test` checks the plan natively: it accepts the OpenSSL examples
(`slh_dsa_examples.cc`), rejects a changed signature, message, context or
key, and its witness satisfies every link.

## Results

These results predate the compute changes of the credential proofs
(`../credential/README.md`, "Compute"), which also apply to `SlhDsaZk`
(except the one-block copies); they were not measured again.

One run of `slh_dsa_zk_test` per parameter set on one Mac (14 cores, 36 GB);
the prover is single-threaded. Peak memory is the peak memory footprint of
`/usr/bin/time -l`.

| Parameter set | Copies | Field, queries | Soundness | Sign | Prove | Verify | Proof | Peak memory |
|---|---|---|---|---|---|---|---|---|
| SLH-DSA-SHAKE-192s | 5,748 | GF(2^256), 281 | 192.1 bits | 1,253 ms | 32.4 s | 3.42 s | 3.07 MB | 2.1 GB |
| SLH-DSA-SHAKE-192f | 17,421 | GF(2^256), 281 | 192.1 bits | 56 ms | 97.9 s | 10.5 s | 7.40 MB | 5.7 GB |
| SLH-DSA-SHAKE-256s | 8,578 | GF(2^384), 374 | 256.4 bits | 1,092 ms | 83.2 s | 8.27 s | 5.87 MB | 4.5 GB |
| SLH-DSA-SHAKE-256f | 17,803 | GF(2^384), 374 | 256.4 bits | 115 ms | 175.6 s | 18.5 s | 10.58 MB | 8.9 GB |

Sign: median native signing of a 32-byte message with the Rust signer of
the C4 scheme (fips205 0.4.1; `revocation::pq_sig`), not with this library.
The s variants sign 9.5 to 22 times slower but prove 2.1 to 3.0 times faster:
signing builds a Merkle tree per layer (2^9 or 2^8 leaves for s, 2^3 or 2^4
for f), while verification, and so the proof, walks every layer (7 or 8 for
s, 22 or 17 for f).

With GF(2^128) and 128 queries (87.1 bits), the four sets proved in 17.9,
53.9, 26.9 and 55.7 s with proofs of 8.0, 23.3, 11.9 and 24.3 MB. For
comparison, ML-DSA (`../ml_dsa`, same harness changes): ML-DSA-65 (Fq^12,
274 queries, 192.0 bits) signs in 0.28 ms and proves in 6.19 s with a
739 KB proof; ML-DSA-87 (Fq^12, 362 queries, 64-byte digests, 256.5 bits)
signs in 0.30 ms and proves in 7.97 s with 944 KB;
with upstream's Fq^6 and 128 queries (88 bits) they took 1.47 s and 1.96 s
with 625 KB and 743 KB.

- The proof is mostly the Ligero column openings: per tableau row and
  query, a 2-byte subfield element for the witness rows and a full element
  (32 or 48 bytes) for the few other rows. The row length is limited by the 16-bit subfield
  of GF(2^128) (`block_enc` < 2^16), so the number of rows grows with the
  witness: 3,421 (n = 24) or 3,485 (n = 32) private inputs per copy.
- Each copy has about 70,000 wires; all but 100 per layer are 0 or 1 in
  every copy, so the packed layers of a 256f proof take about 0.9 GB instead
  of 18.4 GB (with GF(2^128)). No layer is unpacked at full size: the
  sumcheck holds one layer with half the copies (4.3 GB for 256f). The
  Ligero prover keeps row inputs instead of the encoded tableau, and the
  input binding is one product row instead of 62 M terms. The inputs are
  filled packed (one bit per input and copy: 12.6 MB for 256f instead of
  4.8 GB); the prover reads the witness and the public inputs from them in
  place, and the verifier takes the public inputs packed. The peak is now
  the sumcheck: the packed layers and the half-copy buffer (256f: 9.4 GB
  footprint, 6.3 GB resident). The 512-bit capacity
  input (in place of a 1,600-bit previous state) cut proofs by 23%. The
  `eval_quad` shortcuts made proving 1.6 to 1.8 times faster; evaluation
  from the packed layers made it 1.2 times faster again; making its time
  independent of the bit values cost 11%.
- Peak memory is the footprint, which also counts memory macOS compressed or
  the allocator has not returned; the resident peak is close (256f: 9.0 GB
  resident, 8.9 GB footprint).
- The larger fields make proving 1.8 to 3.3 times slower than with
  GF(2^128); the subfield encoding makes the proofs 2.0 to 3.1 times smaller
  than with GF(2^128) and 128 queries. Karatsuba multiplication, the
  packed first copy round and the product row made proving 1.3 to 1.5
  times faster and cut peak memory by 26 to 39%; packed inputs cut it by
  another 25 to 33%.
- The statement is not part of the credential circuits.
