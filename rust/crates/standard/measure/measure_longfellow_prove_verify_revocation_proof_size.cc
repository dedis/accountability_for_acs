// Measure Longfellow ZkProof size for prove_verify + CFT + packed status list
// at selected population scales (default: 2^12, 2^16, 2^20, 2^24).
//
// Build + run:
//   ./communication-costs/build_measure_longfellow_prove_verify_revocation_proof_size.sh
// Optional: REVOC_LOG2_LIST=12,16,20,24  MEASURE_JSON_OUT=/path/to/revocation.json

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "circuits/tests/ec/prove_verify_revocation_shared.h"
#include "util/log.h"

namespace {

std::vector<size_t> parse_scales() {
  const char* env = std::getenv("REVOC_LOG2_LIST");
  std::vector<size_t> out;
  if (!env || !*env) {
    out.push_back(12);
    out.push_back(16);
    out.push_back(20);
    out.push_back(24);
    return out;
  }
  std::string s(env);
  size_t start = 0;
  while (start < s.size()) {
    size_t comma = s.find(',', start);
    if (comma == std::string::npos) comma = s.size();
    std::string tok = s.substr(start, comma - start);
    if (!tok.empty()) out.push_back(static_cast<size_t>(std::stoul(tok)));
    start = comma + 1;
  }
  return out;
}

size_t packed_depth(size_t revoc_log2) {
  // B=253 ⇒ d = ℓ - 7 on the bench grid (see thesis / impl).
  return revoc_log2 - 7;
}

}  // namespace

int main() {
  proofs::set_log_level(proofs::WARNING);
  const auto scales = parse_scales();
  const size_t pub_bytes = proofs::kProveVerifyRevocPublicSize * 32;
  constexpr size_t kCftBytes = 9 * 32;

  std::printf("stack: longfellow-zk\n");
  std::printf("circuit: prove_verify + CFT + packed status-list\n");
  std::printf("public_inputs_bytes (fixed): %zu  (17*32 + 32 root)\n",
              pub_bytes);
  std::printf("cft_bytes: %zu\n", kCftBytes);
  std::printf("\n");

  struct Row {
    size_t ell;
    size_t depth;
    size_t proof_bytes;
  };
  std::vector<Row> rows;
  rows.reserve(scales.size());

  for (size_t ell : scales) {
    std::printf("=== N=2^%zu  packed_depth=%zu ===\n", ell, packed_depth(ell));
    auto h = proofs::MakeProveVerifyRevocationHarnessP256(ell);
    proofs::RefreshProveVerifyRevocationShowP256(*h);
    if (!proofs::ProveProveVerifyRevocationP256(*h)) {
      std::fprintf(stderr, "prove failed at ell=%zu\n", ell);
      return 1;
    }
    const size_t proof_bytes =
        proofs::ProofWireBytesProveVerifyRevocationP256(*h);
    const size_t show = proof_bytes + kCftBytes;
    std::printf("serialized_proof_bytes: %zu\n", proof_bytes);
    std::printf("show_if_proof_plus_cft: %zu\n", show);
    std::printf("\n");
    rows.push_back({ell, packed_depth(ell), proof_bytes});
  }

  const char* path = std::getenv("MEASURE_JSON_OUT");
  if (path && *path) {
    std::ofstream out(path);
    out << "{\n"
        << "  \"circuit\": \"prove_verify + CFT + packed status-list\",\n"
        << "  \"cftBytes\": " << kCftBytes << ",\n"
        << "  \"publicInputsBytes\": " << pub_bytes << ",\n"
        << "  \"byScale\": [\n";
    for (size_t i = 0; i < rows.size(); ++i) {
      const auto& r = rows[i];
      out << "    {\"revocLog2\": " << r.ell << ", \"merkleDepth\": " << r.depth
          << ", \"serializedProofBytes\": " << r.proof_bytes << "}";
      if (i + 1 < rows.size()) out << ",";
      out << "\n";
    }
    out << "  ]\n"
        << "}\n";
  }
  return 0;
}
