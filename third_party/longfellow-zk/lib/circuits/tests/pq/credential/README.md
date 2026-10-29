# Post-quantum credential proofs (not upstream)

Experimental research code: do not use in production.

The credential presentation of the classical benchmark
(`circuits/tests/ec/prove_verify_shared.cc`,
`prove_verify_no_cft_shared.cc`) with post-quantum primitives: ML-DSA or
SLH-DSA signatures, SHAKE256 everywhere, and Module-LWE encryption for the
CFT. These are the proofs of Table IV of the paper, migrated.

## Statement

For one presentation of a credential (`credential.h`: 32 attributes of 32
bytes, leaf i = SHAKE256(be32(i) || attribute i), digest D = SHAKE256 of
the 32 leaves, signed by the issuer):

- the issuer signature on D verifies under the public issuer key;
- BIRTH <= MAX_BIRTH and VALID_FROM <= NOW <= VALID_UNTIL, with NOW and
  MAX_BIRTH public and the three others in attributes 4, 5 and 6
  (`age.h`; the proof hashes these leaves, so the values are bound to D);
- without CFT: a signature on a public 32-byte nonce verifies under a
  private hardware key whose ID = SHAKE256(public key, 64 bytes) is in
  attributes 14 and 15;
- with CFT: the private C4 signature on SHAKE256(T || R2) verifies under a
  private user key whose ID is in attributes 0 and 1, and the public
  ciphertext (U, V) encrypts ID || R2 under the authorities' key (`lwe.h`),
  with the public binding H = SHAKE256(ID || R2) (`cft_binding`).
  T = SHAKE256(be64(NOW) || RID || VERIFIER) is the event tag of the request
  (`event_tag`, `credential.h`, digest-sized), so a show verifies for one
  request of one verifier only; a verifier rejects NOW or MAX_BIRTH of
  2^43 or more. C4 stays private because ML-DSA and SLH-DSA signatures show
  their public key without the message. The authorities verify the stored
  proof before opening, and check the opened ID || R2 against H after.

The private keys are verified in full: for ML-DSA the matrix A is computed
in the circuit from rho (ExpandA, 5 SHAKE128 blocks per polynomial, and
RejNTTPoly with a 5-bit offset per coefficient) and tr = SHAKE256(pk) is
hashed in the circuit; for SLH-DSA, PK.seed and PK.root are private bits
of every hash step.

The Module-LWE parameters (`lwe.h`): q = 8380417, rank 5 and secrets in
[-4, 4] for category 3, rank 7 and [-2, 2] for category 5, three message
polynomials (768 bits: ID || R2). `tools/lwe_estimate.py` (repository root)
checks with the lattice estimator that they cost at least as much to attack
as the Module-LWE instance of ML-DSA-65 and ML-DSA-87.
`Lwe.MatchesTheRustKnownAnswer` checks that `lwe.h` and the Rust
implementation (`crates/pqc/src/lwe.rs`) give the same ciphertext
(`testdata/lwe_kat_3.txt`, `testdata/lwe_kat_5.txt`).

## Design

- `zk/zk_multi.h`: a ZK proof of several circuits, each with copies, over
  one Ligero commitment; extra linear constraints link the private inputs
  of different circuits.
- `sponge.h`: SHAKE128 and SHAKE256 as copies of one Keccak-f step circuit,
  over any field; the state chains between copies by links.
- `statement.h`: references to private inputs (part, copy, input) and the
  links between them, resolved to the committed vector at the end.
- `ml_dsa_cred.h`: one proof over Fq^12 (q = 8380417) with the parts
  sponge, verify (two copies of the ML-DSA verification on mu of
  `../ml_dsa`, with A, t1 and mu private), rej (one copy per polynomial of
  the user's A), age and, with CFT, lwe.
- `slh_dsa_cred.h`: one proof over GF(2^256) or GF(2^384) with the parts
  sponge, age and step (the hash steps of both SLH-DSA verifications,
  `../slh_dsa`, in parts of at most 4,096 copies, the one-block copies in
  their own parts); with CFT, a second proof
  over Fq^12 with a sponge copy and lwe. Both proofs compute the public
  H = SHAKE256(ID || R2), so they encrypt and sign the same ID and R2.
- `ossl_sig.h`: key generation and signing with OpenSSL 3.5 or newer.

Each proof has the soundness of its category (192 or 256 bits, checked by
`pq_credential_test`): Ligero rate 4 with 285 (category 3) or 380
(category 5) queries.

## Memory

The prover's memory is bounded part by part. The proved relation does
not change. The storage changes give the same proof values
(`checkpoint_test` compares the sumcheck with upstream's dense prover;
`ligero_prover_test` the Ligero prover with upstream's); the circuit and
part changes change the sumcheck terms, and `pq_credential_test` checks
the soundness bounds.

- The NTT relations of the ML-DSA verification and of the LWE encryption
  are checked with forward NTTs (`NTT(x) = y` for `INTT(y) = x`): an
  inverse NTT's additions merge into one dense layer (2.4M to 4.2M terms),
  a forward NTT stays layered.
- The SLH-DSA hash steps are split into parts of at most 4,096 copies: the
  sumcheck buffers of a part grow with its copies.
- `PackedLayer` keeps a full wire whose values lie in the base field (Fq
  of Fq^12, GF(2^128) of GF(2^256)) by its base coordinate: 4 instead of
  48 bytes per value for ML-DSA. The first copy round computes the
  products of such wires in the base field (about 20 times fewer
  multiplications).
- The sumcheck prover can checkpoint layers (`prove_low_memory`, stride
  per part); the credential proofs keep every layer, which the two changes
  above make small, as checkpointing costs one more evaluation.
- The Ligero linear test builds its vector one row at a time
  (`LigeroRows`) instead of in full (one element per committed witness).
- The links are 12 bytes per term (`LigeroUnitTerm`: every coefficient is
  +-1), passed to Ligero without copies; the statement is freed once the
  inputs are filled; an SLH-DSA copy keeps only the last Keccak-f state.
- Circuits are compiled once (`../circuit_cache.h`, `circuit_cache_test`):
  with `PQ_CIRCUIT_CACHE` set to a directory, a program stores each
  circuit it compiles (`proto/circuit_writer.h`) and later processes load
  it (`proto/circuit_reader.h`, circuit ID checked). The file name holds the
  copies, the values compiled into the circuit (the LWE public key) and a
  hash of the executable, so another build never loads it. Compiling a
  circuit takes several times the memory of the proof; the Rust drivers set
  the variable, so the warm-up compiles and the measured run loads. The
  benchmarks use one fixed LWE authority key, so its circuit is compiled
  once.

## Compute

The prover and verifier work was cut without a change of soundness: the
Ligero parameters, the fields and the proved relation are those above.
Unless noted, a change gives the same proof values (tests in brackets).

- Field arithmetic. Fq^12: products by an integer Karatsuba (81 instead of
  144 products), on AArch64 a NEON schoolbook with every sum in a register
  (3 times faster than Karatsuba there), and Barrett reduction in Fq
  [`fp24_ext_test`]. GF(2^256) and GF(2^384): the Karatsuba products of
  GF(2^128) are summed unreduced and alpha = x^k is a shift (18 instead of
  24, 34 instead of 48 carry-less products) [`extension_field_test`]. Both
  fields have an accumulator (`Acc`: products summed before one reduction),
  used by the sumcheck and the Reed-Solomon evaluation.
- Sumcheck copy rounds (`sumcheck/prover_layers.h`). EQ is factored out of
  every pair of copies whose EQ values are a product (Gruen): the prover
  tracks the claim of each round and computes the round polynomial from
  H(T) and the X^2 coefficient of H, 4 instead of 6 products per term and
  pair (the 2 extension products by evaluation points of GF(2^k) too); the
  wire of a run of terms is scaled by EQ once. The first two copy rounds
  read the packed layer: after round 0 a wire is a + R0 d with a, d bits or
  base elements, so round 1 sums bits by classes (GF(2^k)) or base-field
  products (Fq^12), and both rounds are bound at once into a buffer of a
  quarter of the copies [`checkpoint_test`: the dense upstream prover gives
  the same proof for 1, 2, 3, 8, 37 and 64 copies with a random pad, and a
  changed witness bit fails].
- Layer evaluation. GF(2^k): an output wire that is a XOR of ANDs of bit
  wires is computed 64 copies per word. Fq^12: an output wire of base-field
  coefficients and wires is computed in Fq [`checkpoint_test`,
  `EvalShortcutsMatchReference`].
- Ligero. A coordinate that is zero in a message (coordinates 1 to K - 1 of
  the base-field witness rows) is not encoded. The CRT FFT keeps its
  twiddles and buffers. The witness rows, which lie in the subfield, are
  hashed into the Merkle leaves by their subfield bytes (2 instead of 32 or
  48 bytes; `LigeroParam::nsub`), and the verifier rejects an opened element
  of these rows outside the subfield, so the leaves still determine the
  columns: a different leaf hash, the same proof format and soundness
  [`ligero_prover_test`: both leaf formats against the upstream prover, and
  the rejection]. GF(2^128) subfield bytes come from a table (16 loads
  instead of an elimination per element). The Fq^12 verifier evaluates the
  linear-test rows at the opened columns alone (`interpolate_at`) instead
  of encoding every coordinate [`fp24_ext_test`].
- Transcript. A public wire that is 0 or 1 in every copy is written as its
  bits (a byte string) instead of one tagged field element per copy: an
  injective encoding, as before, with 8 (1 + field bytes) = 264 to 392
  times fewer bytes (the SLH-DSA-192s public inputs were 2 GB per proof,
  hashed by the prover and by the verifier); the other hashes are fed 4 KB
  at a time [`zk_multi_test`]. The proof values change, not its format.
- `Quad::bind_gh_all` (the verifier's bound quad) sums the coefficients of
  one pair of hands before its two products, and multiplies by a base-field
  coefficient with base products.
- SLH-DSA one-block copies (`../slh_dsa/README.md`): the F and H calls
  commit 1,053 (n = 24) or 1,309 (n = 32) private bits instead of 3,421 or
  3,485; the step parts hold the general copies first, then the one-block
  copies [`slh_dsa_test`: the links on the one-block plans;
  `slh_dsa_zk_test` `OneBlockStep`: the circuit holds on each kind of copy
  and fails with a changed R or private block bit].

Not done: multithreading (excluded); the hybrid ML-DSA proof (Keccak in a
binary field, a new cross-field link that needs its own soundness
argument); a smaller Ligero rate, a larger `block_enc` and Fq^11 (fewer
soundness bits); an SLH-DSA "s" issuer key (another parameter set);
two-valued Fq wires stored as bits (96% of the base wires of the ML-DSA sponge, about
5% of its proving time by the profiles); a GF(2^16) FFT for the subfield
rows and a pruned FFT for the opened columns (about 28% of the SLH-DSA
verifier's encoding).

Changes outside this directory:

| File | Change |
|---|---|
| `zk/zk_multi.h` | New: proofs of several circuits over one commitment, a checkpoint stride per part; the Ligero parameters with the subfield rows (`ZkMultiLayout::ligero_param`) |
| `zk/zk_common.h` | The input binding of a circuit can start at a witness offset; extra constraints are unit terms; public bit wires in the transcript as bits; `extra_hash` by 4 KB |
| `zk/zk_prover.h`, `zk/zk_verifier.h` | Extra constraints passed to Ligero as unit terms, without copies |
| `zk/zk_proof.h` | The serialization helpers are static, for `zk_multi.h` |
| `zk/zk_soundness.h` | Soundness of several circuits over one commitment |
| `ligero/*` | Several product rows; linear terms as spans and unit terms; the linear-test vector one row at a time (`LigeroRows`); subfield rows hashed by subfield bytes (`nsub`), checked by the verifier; the dot check at the opened columns alone when the code can |
| `sumcheck/prover_layers.h` | Layer checkpointing; the first copy round in the base field; copy rounds with EQ factored out and the claim tracked; the second copy round from the packed layer; word and base-field layer evaluation; accumulated hand-round sums |
| `sumcheck/quad.h` | `bind_gh_all` grouped by hands; base-field coefficients by base products |
| `arrays/packed_layer.h` | Full wires in the base field kept by their base coordinate; `set_bits`, `set_base`, `in_base` |
| `algebra/base_coordinates.h` | New: `BaseCoordinates` (moved), `MacOf` (accumulated sums), `mul_coefficient` |
| `algebra/fp24.h`, `algebra/fp24_ext.h` | Barrett reduction; Karatsuba and NEON products; `Acc`, `mac`, `mac_backward`, `reduce` |
| `gf2k/gf2_128.h`, `gf2k/sysdep.h`, `gf2k/gf2_128_ext.h` | Unreduced products (`Wide`); `solve` by table; extension products by `combine`, alpha as a shift; `Acc` |
| `algebra/reed_solomon.h`, `algebra/reed_solomon_componentwise.h` | Coefficient accessors and kept buffers; zero coordinates not encoded; `interpolate_at` |
| `algebra/fft.h`, `algebra/crt_convolution.h` | Twiddles and buffers kept by the convolution |
| `random/transcript.h` | `write_each`: many field elements in few hash updates |
| `../slh_dsa/slh_dsa.h` | External key and message bits (`Bit::kExt`); a public signature as private bits fixed to their values (`Bit::kFixed`); a copy keeps only the round-23 Keccak-f state; one-block copies (`Layout1`, `one_block`) |
| `../slh_dsa/slh_dsa_circuit.h`, `../slh_dsa/slh_dsa_zk.h` | `OneBlockStepCircuit`; its inputs and circuit (`fill_public1`, `fill_private1`, `make_circuit1`); circuits stored once (`stored_circuit`) |
| `../circuit_cache.h` | New: circuits compiled once and stored (`cached_circuit`, `PQ_CIRCUIT_CACHE`) |
| `proto/circuit_io.h` | Field IDs of Fq^12, GF(2^256) and GF(2^384) |
| `../ml_dsa/ml_dsa_zk_harness.h` | The circuit stored once (`cached_circuit`) |
| `../ml_dsa/ml_dsa_circuit.h` | `w'_approx` checked with a forward NTT; unsigned loop indices (no `-Wsign-compare` warning) |
| `../ml_dsa/ml_dsa_witness.h` | Signed casts (no `-Wsign-compare` warning) |

## Build and run

```bash
cmake -S third_party/longfellow-zk/lib -B .work/standard/longfellow-build \
  -DCMAKE_BUILD_TYPE=Release
cmake --build .work/standard/longfellow-build -j 8 \
  --target zk_multi_test sponge_test checkpoint_test circuit_cache_test \
           pq_credential_test pq_credential_5_test
B=.work/standard/longfellow-build/circuits/tests/pq/credential
$B/zk_multi_test && $B/sponge_test && $B/checkpoint_test && $B/circuit_cache_test
$B/pq_credential_test          # category 3: ML-DSA-65, SLH-DSA-SHAKE-192s
# The first run compiles and stores the circuits, the next ones load them.
PQ_CIRCUIT_CACHE=/tmp/pq-circuits \
  $B/pq_credential_test --benchmark_filter='BM_Combined_PQCred_MLDSA_Cft$' --benchmark_min_time=1x
```

`pq_credential_test` has 48-byte digests (ML-DSA-65, SLH-DSA-SHAKE-192s,
192f) and `pq_credential_5_test` 64-byte digests (ML-DSA-87, 256s, 256f).
The benchmarks `BM_Combined_PQCred_{MLDSA,SLHs,SLHf}_{NoCft,Cft}` time one
presentation per repetition: the per-show signature (nonce or C4) and
encryption plus the proof as `prove_ns`, and the verification of the
serialized proof (including building the statement) as `verify_ns`. The
Rust drivers are `standard_pq_prove_verify` and
`standard_pq_prove_verify_no_cft` (`crates/standard`).
