#!/usr/bin/env bash
# Shared helpers for Longfellow proof-size measure scripts.
# Sourced by build_measure_longfellow_*.sh (expects SCRIPT_DIR already set).

# standard_communication_size sets both paths (crates/standard/src/paths.rs).
LIB="${LONGFELLOW_LIB:?set LONGFELLOW_LIB to third_party/longfellow-zk/lib}"
BLD="${LONGFELLOW_BUILD_DIR:?set LONGFELLOW_BUILD_DIR to the Longfellow CMake build}"

CXX_BIN="${CXX:-c++}"

# OpenSSL / zstd: Homebrew on macOS; system paths on Debian/Ubuntu (Docker).
OPENSSL_INC="${OPENSSL_INC:-}"
LINK_LIB_DIRS=()
if [[ -z "${OPENSSL_INC}" ]]; then
  if [[ -d /opt/homebrew/include/openssl ]]; then
    OPENSSL_INC="-I/opt/homebrew/include"
    LINK_LIB_DIRS+=("-L/opt/homebrew/lib")
  elif [[ -d /usr/local/opt/openssl@3/include ]]; then
    OPENSSL_INC="-I/usr/local/opt/openssl@3/include"
    LINK_LIB_DIRS+=("-L/usr/local/opt/openssl@3/lib")
  fi
fi
