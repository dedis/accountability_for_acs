// Measure serialized Longfellow ZkProof size for prove_verify (age-check + CFT).
//
// Build + run:
//   ./communication-costs/build_measure_longfellow_prove_verify_proof_size.sh
// Optional: MEASURE_JSON_OUT=/path/to/cft_only.json

#include <cstdio>
#include <cstdlib>
#include <fstream>

#include "circuits/tests/ec/prove_verify_shared.h"
#include "util/log.h"

namespace proofs {

static void print_public_inputs_table() {
  static const char* kNames[] = {
      "dummy_pub",     "issuer_pub_x",  "issuer_pub_y",  "elgamal_pub_x",
      "elgamal_pub_y", "t_pub",         "c1x",           "c1y",
      "c2x",           "c2y",           "c3x",           "c3y",
      "c4_rx",         "c4_ry",         "c4_s",          "now_pub",
      "max_birth_pub",
  };
  constexpr size_t kN = sizeof(kNames) / sizeof(kNames[0]);
  printf("public_inputs (separate from proof blob, 32 bytes each):\n");
  for (size_t i = 0; i < kN; ++i) {
    printf("  [%zu] %-16s 32 B\n", i, kNames[i]);
  }
  printf("  total raw public inputs: %zu B\n", kN * 32);
  printf("  of which CFT (c1..c4): %zu B\n", 9 * 32);
}

static void write_json(size_t proof_bytes) {
  const char* path = std::getenv("MEASURE_JSON_OUT");
  if (!path || !*path) return;

  constexpr size_t kPubCount = 17;
  constexpr size_t kCftBytes = 9 * 32;
  const size_t pub_bytes = kPubCount * 32;
  std::ofstream out(path);
  out << "{\n"
      << "  \"circuit\": \"prove_verify (age-check + CFT)\",\n"
      << "  \"proof\": {\n"
      << "    \"serializedProofBytes\": " << proof_bytes << ",\n"
      << "    \"note\": \"ZkProof::write after one prove\"\n"
      << "  },\n"
      << "  \"publicInputs\": {\n"
      << "    \"count\": " << kPubCount << ",\n"
      << "    \"binaryBytes\": " << pub_bytes << ",\n"
      << "    \"cftBytes\": " << kCftBytes << "\n"
      << "  },\n"
      << "  \"showMessageIfProofPlusAllPublic\": "
      << (proof_bytes + pub_bytes) << ",\n"
      << "  \"showMessageIfProofPlusCftOnlyCachedKeys\": "
      << (proof_bytes + kCftBytes) << "\n"
      << "}\n";
}

}  // namespace proofs

int main() {
  proofs::set_log_level(proofs::INFO);
  auto h = proofs::MakeCredentialCommitmentProveVerifyHarnessP256(1);
  proofs::RebuildBenchmarkCredentialP256(*h);
  if (!proofs::ProveVerifyP256(*h)) {
    fprintf(stderr, "prove failed\n");
    return 1;
  }
  const size_t proof_bytes = proofs::ProofWireBytesProveVerifyP256(*h);
  if (proof_bytes == 0) {
    fprintf(stderr, "empty proof\n");
    return 1;
  }
  printf("stack: longfellow-zk\n");
  printf("circuit: prove_verify (age-check + CFT)\n");
  printf("serialized_proof_bytes (ZkProof::write): %zu\n", proof_bytes);
  proofs::print_public_inputs_table();
  printf("show_message_binary_bytes (proof + public): %zu\n",
         proof_bytes + 17 * 32);
  printf("note: public inputs are not included in serialized_proof_bytes\n");
  printf(
      "note: pk_CFT and pk_issuer appear in public inputs but may be cached "
      "out-of-band\n");
  proofs::write_json(proof_bytes);
  return 0;
}
