// Circuits compiled once and stored (not upstream).
//
// With the environment variable PQ_CIRCUIT_CACHE set to a directory,
// cached_circuit(f, key, make) loads <dir>/<key>-f<field id>-<tag>.circuit
// (proto/circuit_reader.h, circuit ID checked), or calls make() and stores
// the circuit there. <tag> is part of the SHA-256 of this executable, so a
// rebuilt program never loads the circuit of another build. KEY must name
// what make() depends on that the executable does not fix: the number of
// copies and the values compiled into the circuit (object_tag()). Without
// the variable, cached_circuit() returns make().
//
// A cached circuit is trusted: a planted circuit without constraints would
// make Verify accept false statements. So the directory must belong to the
// user and must not be writable by others; it is created with mode 0700.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CIRCUIT_CACHE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CIRCUIT_CACHE_H_

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#include "proto/circuit_io.h"
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
#include "sumcheck/circuit.h"
#include "util/crypto.h"
#include "util/panic.h"
#include "util/readbuffer.h"

namespace proofs {

template <size_t K>
class Fp24Ext;
template <size_t D>
class GF2_128Ext;

// The FieldID of the circuit files of a proof field.
template <class Field>
constexpr FieldID circuit_field_id() {
  if constexpr (std::is_same_v<Field, Fp24Ext<12>>) {
    return FP24_12_ID;
  } else if constexpr (std::is_same_v<Field, GF2_128Ext<2>>) {
    return GF2_128_2_ID;
  } else {
    static_assert(std::is_same_v<Field, GF2_128Ext<3>>, "no FieldID");
    return GF2_128_3_ID;
  }
}

// The first 8 bytes of the digest of H, in hex.
inline std::string hex_tag(SHA256& h) {
  uint8_t d[kSHA256DigestSize];
  h.DigestData(d);
  char hex[17];
  for (size_t i = 0; i < 8; ++i) snprintf(hex + 2 * i, 3, "%02x", d[i]);
  return std::string(hex, 16);
}

// The tag of the bytes of X, for a key: X has no padding.
template <class T>
std::string object_tag(const T& x) {
  static_assert(std::has_unique_object_representations_v<T>,
                "object_tag needs a type without padding");
  SHA256 h;
  h.Update(reinterpret_cast<const uint8_t*>(&x), sizeof(T));
  return hex_tag(h);
}

// The tag of this executable, computed once.
inline const std::string& executable_tag() {
  static const std::string tag = [] {
#if defined(__APPLE__)
    uint32_t n = 0;
    _NSGetExecutablePath(nullptr, &n);
    std::string path(n, '\0');
    check(_NSGetExecutablePath(path.data(), &n) == 0, "executable path");
    path.resize(std::strlen(path.c_str()));
#else
    const std::string path = "/proc/self/exe";
#endif
    std::ifstream in(path, std::ios::binary);
    check(in.is_open(), "cannot open the executable");
    SHA256 h;
    std::vector<char> buf(size_t(1) << 20);
    while (in.read(buf.data(), buf.size()) || in.gcount() > 0) {
      h.Update(reinterpret_cast<const uint8_t*>(buf.data()),
               size_t(in.gcount()));
    }
    check(in.eof() && !in.bad(), "cannot read the executable");
    return hex_tag(h);
  }();
  return tag;
}

template <class Field, class Make>
std::unique_ptr<Circuit<Field>> cached_circuit(const Field& f,
                                               const std::string& key,
                                               const Make& make) {
  const char* dir = std::getenv("PQ_CIRCUIT_CACHE");
  if (dir == nullptr || *dir == '\0') return make();
  {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
      std::filesystem::create_directories(dir, ec);
      check(!ec, "cannot create PQ_CIRCUIT_CACHE");
      std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                   std::filesystem::perm_options::replace, ec);
      check(!ec, "cannot set the mode of PQ_CIRCUIT_CACHE");
    }
    struct stat st;
    check(stat(dir, &st) == 0 && S_ISDIR(st.st_mode),
          "PQ_CIRCUIT_CACHE is not a directory");
    check(st.st_uid == geteuid() && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0,
          "PQ_CIRCUIT_CACHE must belong to the user and not be writable by "
          "others");
  }
  constexpr FieldID kId = circuit_field_id<Field>();
  const std::filesystem::path path =
      std::filesystem::path(dir) /
      (key + "-f" + std::to_string(int(kId)) + "-" + executable_tag() +
       ".circuit");
  std::error_code ec;
  if (std::filesystem::exists(path, ec)) {
    // Mapped, not read: the file takes no heap memory.
    const int fd = open(path.c_str(), O_RDONLY);
    check(fd >= 0, "cannot open a cached circuit");
    struct stat st;
    check(fstat(fd, &st) == 0 && st.st_size > 0,
          "cannot stat a cached circuit");
    const size_t n = size_t(st.st_size);
    void* m = mmap(nullptr, n, PROT_READ, MAP_PRIVATE, fd, 0);
    check(close(fd) == 0 && m != MAP_FAILED, "cannot map a cached circuit");
    ReadBuffer rb(static_cast<const uint8_t*>(m), n);
    auto c = CircuitReader<Field>(f, kId).from_bytes(
        rb, /*enforce_circuit_id=*/true);
    check(munmap(m, n) == 0, "cannot unmap a cached circuit");
    check(c != nullptr, "corrupt cached circuit: delete PQ_CIRCUIT_CACHE");
    return c;
  }
  check(!ec, "cannot stat PQ_CIRCUIT_CACHE");
  auto c = make();
  std::vector<uint8_t> bytes;
  CircuitWriter<Field>(f, kId).to_bytes(*c, bytes);
  // Written under another name, then renamed: no reader sees a part.
  const std::string tmp = path.string() + ".tmp" + std::to_string(getpid());
  {
    std::ofstream out(tmp, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              std::streamsize(bytes.size()));
    out.close();
    check(out.good(), "cannot write a cached circuit");
  }
  std::filesystem::rename(tmp, path, ec);
  check(!ec, "cannot store a cached circuit");
  return c;
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CIRCUIT_CACHE_H_
