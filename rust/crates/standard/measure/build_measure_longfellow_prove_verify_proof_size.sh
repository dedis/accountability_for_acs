#!/usr/bin/env bash
# Build and run Longfellow prove_verify proof size measurement.
# Run through standard_communication_size, which sets the Longfellow paths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=measure_common.sh
source "${SCRIPT_DIR}/measure_common.sh"

if [[ ! -x "${BLD}/circuits/tests/ec/prove_verify_test" ]]; then
  echo "Build longfellow-zk first:" >&2
  echo "  cmake -S ${LIB} -B ${BLD} -DCMAKE_BUILD_TYPE=Release && cmake --build ${BLD} -j --target prove_verify_test" >&2
  exit 1
fi

echo "Rebuilding prove_verify_test (picks up ProofWireBytes) ..."
cmake --build "${BLD}" -j --target prove_verify_test

MEASURE_CC="${SCRIPT_DIR}/measure_longfellow_prove_verify_proof_size.cc"
OUT_BIN="${BLD}/measure_longfellow_prove_verify_proof_size"
TEST_DIR="${BLD}/circuits/tests/ec/CMakeFiles/prove_verify_test.dir"

echo "Compiling ${OUT_BIN} ..."
"${CXX_BIN}" -std=gnu++20 -O3 -DNDEBUG \
  -I"${LIB}" -I"${BLD}" ${OPENSSL_INC} \
  -c "${MEASURE_CC}" -o /tmp/measure_prove_verify_main.o

"${CXX_BIN}" -std=gnu++20 -O3 \
  /tmp/measure_prove_verify_main.o \
  "${TEST_DIR}/prove_verify_shared.cc.o" \
  "${BLD}/ec/CMakeFiles/ec.dir/p256.cc.o" \
  "${BLD}/ec/CMakeFiles/ec.dir/p256k1.cc.o" \
  "${BLD}/algebra/CMakeFiles/algebra.dir/nat.cc.o" \
  "${BLD}/algebra/CMakeFiles/algebra.dir/crt.cc.o" \
  "${BLD}/util/CMakeFiles/util.dir/log.cc.o" \
  "${BLD}/util/CMakeFiles/util.dir/crypto.cc.o" \
  "${BLD}/circuits/sha/CMakeFiles/flatsha.dir/flatsha256_witness.cc.o" \
  "${BLD}/circuits/sha/CMakeFiles/flatsha.dir/sha256_constants.cc.o" \
  "${LINK_LIB_DIRS[@]}" -lcrypto -lzstd \
  -o "${OUT_BIN}"

echo "Running (prove once; may take ~1–2 min) ..."
# Optional: MEASURE_JSON_OUT=/path/to/cft_only.json
"${OUT_BIN}"
