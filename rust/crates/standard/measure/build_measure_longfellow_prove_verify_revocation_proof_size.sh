#!/usr/bin/env bash
# Build and run Longfellow prove_verify+revocation proof size measurement.
# Default scales: 2^12, 2^16, 2^20, 2^24. Override with REVOC_LOG2_LIST=...
# Run through standard_communication_size, which sets the Longfellow paths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=measure_common.sh
source "${SCRIPT_DIR}/measure_common.sh"

MEASURE_CC="${SCRIPT_DIR}/measure_longfellow_prove_verify_revocation_proof_size.cc"
OUT_BIN="${BLD}/measure_longfellow_prove_verify_revocation_proof_size"

if [[ ! -x "${BLD}/circuits/tests/ec/prove_verify_revocation_test" ]]; then
  echo "Build longfellow-zk first:" >&2
  echo "  cmake -S ${LIB} -B ${BLD} -DCMAKE_BUILD_TYPE=Release && cmake --build ${BLD} -j --target prove_verify_revocation_test" >&2
  exit 1
fi

echo "Rebuilding prove_verify_revocation_test ..."
cmake --build "${BLD}" -j --target prove_verify_revocation_test

TEST_DIR="${BLD}/circuits/tests/ec/CMakeFiles/prove_verify_revocation_test.dir"
echo "Compiling ${OUT_BIN} ..."
"${CXX_BIN}" -std=gnu++20 -O3 -DNDEBUG \
  -I"${LIB}" -I"${BLD}" ${OPENSSL_INC} \
  -c "${MEASURE_CC}" -o /tmp/measure_pvr_main.o

"${CXX_BIN}" -std=gnu++20 -O3 \
  /tmp/measure_pvr_main.o \
  "${TEST_DIR}/prove_verify_revocation_shared.cc.o" \
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

echo "Running (one prove per scale; may take several minutes) ..."
# Optional: MEASURE_JSON_OUT=/path/to/revocation.json
REVOC_LOG2_LIST="${REVOC_LOG2_LIST:-12,16,20,24}" "${OUT_BIN}"
