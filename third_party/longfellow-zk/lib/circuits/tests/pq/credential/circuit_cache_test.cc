// cached_circuit (circuits/tests/pq/circuit_cache.h; not upstream): with
// PQ_CIRCUIT_CACHE, the first call compiles and stores the circuit, the next
// calls load it, term for term the same, over GF(2^256) and Fq^12. Another
// key compiles again; without the variable every call compiles; a changed
// file is rejected.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <unistd.h>

#include "algebra/fp24_ext.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/circuit_cache.h"
#include "circuits/tests/pq/credential/sponge.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "gf2k/gf2_128_ext.h"
#include "sumcheck/circuit.h"
#include "gtest/gtest.h"

namespace proofs {
namespace pq_cred {
namespace {

// The sponge-step circuit (sponge.h) for NC copies.
template <class Field>
std::unique_ptr<Circuit<Field>> MakeSponge(const Field& f, size_t nc) {
  using LC = Logic<Field, CompilerBackend<Field>>;
  QuadCircuit<Field> Q(f);
  const CompilerBackend<Field> cbk(&Q);
  const LC lc(&cbk, f);
  typename SpongeStep<LC>::Public u;
  typename SpongeStep<LC>::Private w;
  Sponge<Field>::inputs(lc, Q, u, w);
  Q.begin_full_field();
  SpongeStep<LC>(lc).assert_step(u, w);
  return Q.mkcircuit(nc);
}

template <class Field>
void ExpectSame(const Circuit<Field>& a, const Circuit<Field>& b) {
  EXPECT_EQ(memcmp(a.id, b.id, sizeof(a.id)), 0);
  EXPECT_EQ(a.nv, b.nv);
  EXPECT_EQ(a.logv, b.logv);
  EXPECT_EQ(a.nc, b.nc);
  EXPECT_EQ(a.logc, b.logc);
  EXPECT_EQ(a.ninputs, b.ninputs);
  EXPECT_EQ(a.npub_in, b.npub_in);
  EXPECT_EQ(a.subfield_boundary, b.subfield_boundary);
  ASSERT_EQ(a.nl, b.nl);
  ASSERT_EQ(a.l.size(), b.l.size());
  for (size_t ly = 0; ly < a.l.size(); ++ly) {
    EXPECT_EQ(a.l[ly].nw, b.l[ly].nw);
    EXPECT_EQ(a.l[ly].logw, b.l[ly].logw);
    ASSERT_EQ(a.l[ly].nterms(), b.l[ly].nterms());
    auto i = a.l[ly].quad->begin();
    auto j = b.l[ly].quad->begin();
    for (size_t t = 0; t < a.l[ly].nterms(); ++t, ++i, ++j) {
      const auto x = *i, y = *j;
      ASSERT_TRUE(x.g == y.g && x.h[0] == y.h[0] && x.h[1] == y.h[1] &&
                  x.v == y.v)
          << "layer " << ly << " term " << t;
    }
  }
}

template <class Field>
void RoundTrip(const Field& f) {
  const std::filesystem::path dir =
      std::filesystem::temp_directory_path() /
      ("circuit_cache_test_" + std::to_string(getpid()));
  std::filesystem::remove_all(dir);
  ASSERT_EQ(setenv("PQ_CIRCUIT_CACHE", dir.c_str(), 1), 0);
  size_t compiled = 0;
  auto make = [&](size_t nc) {
    ++compiled;
    return MakeSponge(f, nc);
  };
  const auto c3 = cached_circuit(f, "sponge_nc3", [&] { return make(3); });
  EXPECT_EQ(compiled, 1u);
  const auto again = cached_circuit(f, "sponge_nc3", [&] { return make(3); });
  EXPECT_EQ(compiled, 1u);
  ExpectSame(*c3, *again);
  const auto c2 = cached_circuit(f, "sponge_nc2", [&] { return make(2); });
  EXPECT_EQ(compiled, 2u);
  EXPECT_EQ(c2->nc, 2u);

  // A changed byte in a stored circuit: loading fails (circuit ID).
  std::vector<std::filesystem::path> files;
  for (const auto& e : std::filesystem::directory_iterator(dir)) {
    files.push_back(e.path());
  }
  ASSERT_EQ(files.size(), 2u);
  for (const auto& p : files) {
    if (p.filename().string().rfind("sponge_nc3", 0) != 0) continue;
    std::fstream io(p, std::ios::in | std::ios::out | std::ios::binary);
    const auto at = std::streamoff(std::filesystem::file_size(p) / 2);
    io.seekg(at);
    const char x = char(io.get());
    io.seekp(at);
    io.put(char(x ^ 0x5a));
    ASSERT_TRUE(io.good());
  }
  EXPECT_DEATH(cached_circuit(f, "sponge_nc3", [&] { return make(3); }),
               "corrupt cached circuit");

  ASSERT_EQ(unsetenv("PQ_CIRCUIT_CACHE"), 0);
  cached_circuit(f, "sponge_nc3", [&] { return make(3); });
  EXPECT_EQ(compiled, 3u);
  std::filesystem::remove_all(dir);
}

TEST(CircuitCache, RoundTripGf2) { RoundTrip(GF2_128Ext<2>()); }

TEST(CircuitCache, RoundTripFq12) {
  RoundTrip(Fp24Ext<12>(ml_dsa::Fq(), 7));
}

}  // namespace
}  // namespace pq_cred
}  // namespace proofs
