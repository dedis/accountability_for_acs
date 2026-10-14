// ML-DSA-87 example for the ML-DSA-87 ZK benchmark (not upstream).

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_87_EXAMPLES_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_87_EXAMPLES_H_

#include <cstdint>
#include <vector>

namespace proofs {
namespace ml_dsa_87 {

struct MlDsa87SignatureExample {
  std::vector<uint8_t> msg;
  std::vector<uint8_t> pkey;
  std::vector<uint8_t> ctx;
  std::vector<uint8_t> sig;
};

std::vector<MlDsa87SignatureExample> GetMlDsa87Examples();

}  // namespace ml_dsa_87
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_87_EXAMPLES_H_
