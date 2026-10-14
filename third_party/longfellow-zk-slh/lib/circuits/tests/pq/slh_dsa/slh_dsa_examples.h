// SLH-DSA examples for the SLH-DSA proofs (not upstream).

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_EXAMPLES_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_EXAMPLES_H_

#include <cstdint>
#include <vector>

namespace proofs {
namespace slh_dsa {

struct Example {
  std::vector<uint8_t> msg;
  std::vector<uint8_t> pk;
  std::vector<uint8_t> ctx;
  std::vector<uint8_t> sig;
};

// One example per SHAKE parameter set.
Example Example192s();
Example Example192f();
Example Example256s();
Example Example256f();

}  // namespace slh_dsa
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_EXAMPLES_H_
