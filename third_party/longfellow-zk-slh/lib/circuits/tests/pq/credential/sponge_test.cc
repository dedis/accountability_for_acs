// The sponge copies (sponge.h): native outputs against the SHA3 reference,
// and proofs over GF(2^256) and Fq^12.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/fp24_ext.h"
#include "arrays/packed_layer.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/credential/sponge.h"
#include "circuits/tests/pq/credential/statement.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_zk_harness.h"
#include "circuits/tests/pq/slh_dsa/slh_dsa_zk.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "gf2k/gf2_128_ext.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_multi.h"
#include "gtest/gtest.h"

namespace proofs {
namespace pq_cred {
namespace {

constexpr size_t kRate = 4;
constexpr size_t kQueries = 64;

std::vector<uint8_t> pattern(size_t n, uint8_t seed) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(seed + 31 * i);
  return v;
}

TEST(Sponge, MatchesReference) {
  const GF2_128Ext<2> f;
  for (size_t len : {0, 1, 135, 136, 137, 167, 168, 169, 300, 1952}) {
    for (size_t out : {32, 48, 64, 200, 840}) {
      const auto msg = pattern(len, static_cast<uint8_t>(len));
      Links<GF2_128Ext<2>> links(f);
      Sponge<GF2_128Ext<2>> sp(0, links);
      std::vector<uint8_t> want(out);
      const Bytes in = free_bytes(msg.data(), len);
      EXPECT_EQ(values(sp.shake(kShake256Rate, in, out)),
                (Sha3Reference::shake256Hash(msg.data(), len, want.data(), out),
                 want))
          << "SHAKE256 len " << len << " out " << out;
      EXPECT_EQ(values(sp.shake(kShake128Rate, in, out)),
                (Sha3Reference::shake128Hash(msg.data(), len, want.data(), out),
                 want))
          << "SHAKE128 len " << len << " out " << out;
    }
  }
}

struct Gf2 {
  using Field = GF2_128Ext<2>;
  using RS = slh_dsa::ZkRs<Field>;
  const Field f;
  const RS rs{f};
  const typename RS::Factory& factory() const { return rs.factory; }
};

struct Fq12 {
  using Field = Fp24Ext<12>;
  using RS = MlDsaRs<Field>;
  const Field f{ml_dsa::Fq(), 7};
  const RS rs{ml_dsa::Fq()};
  const typename RS::Factory& factory() const { return rs.factory; }
};

template <class Env>
class SpongeProof : public ::testing::Test {
 protected:
  using Field = typename Env::Field;
  using LC = Logic<Field, CompilerBackend<Field>>;
  using Step = SpongeStep<LC>;

  std::unique_ptr<Circuit<Field>> circuit(size_t nc) const {
    QuadCircuit<Field> Q(env_.f);
    const CompilerBackend<Field> cbk(&Q);
    const LC lc(&cbk, env_.f);
    typename Step::Public u;
    typename Step::Private w;
    Sponge<Field>::inputs(lc, Q, u, w);
    Q.begin_full_field();
    Step(lc).assert_step(u, w);
    return Q.mkcircuit(nc);
  }

  // Proves SHAKE256 of a 300-byte private message (3 copies), then
  // SHAKE128 of a message whose first 32 bytes are the first 32 output
  // bytes, squeezed to 400 bytes (1 absorb and 2 squeeze copies). With
  // BREAK, the native value of a linked data byte is changed after the
  // links are made, so the witness violates a link.
  bool run(bool brk) const {
    Links<Field> links(env_.f);
    Sponge<Field> sp(0, links);
    const auto msg = pattern(300, 7);
    const Bytes out = sp.shake(kShake256Rate, free_bytes(msg.data(), 300), 64);
    const auto tail = pattern(10, 9);
    const Bytes t = const_bytes(tail.data(), tail.size());
    const Bytes head = slice(out, 0, 32);
    sp.shake(kShake128Rate, cat({&head, &t}), 400);
    auto copies = sp.copies();
    EXPECT_EQ(copies.size(), 6u);

    auto c = circuit(copies.size());
    const ZkMultiLayout<Field> lay({c.get()});
    PackedLayer<Field> w(c->nc, c->ninputs, env_.f);
    PackedLayer<Field> pub(c->nc, c->npub_in, env_.f);
    for (size_t k = 0; k < c->nc; ++k) {
      sp.fill(w, k, false);
      sp.fill(pub, k, true);
    }
    if (brk) {
      // The same copies with bit 0 of the absorbed head flipped: every copy
      // holds alone, but copy 3 no longer absorbs the output of copy 2.
      PackedLayer<Field> w2(c->nc, c->ninputs, env_.f);
      Links<Field> l2(env_.f);
      Sponge<Field> sp2(0, l2);
      const Bytes out2 =
          sp2.shake(kShake256Rate, free_bytes(msg.data(), 300), 64);
      Bytes head2 = slice(out2, 0, 32);
      head2[0].value = !head2[0].value;
      sp2.shake(kShake128Rate, cat({&head2, &t}), 400);
      for (size_t k = 0; k < c->nc; ++k) sp2.fill(w2, k, false);
      return prove_verify(lay, w2, pub, links);
    }
    return prove_verify(lay, w, pub, links);
  }

  bool prove_verify(const ZkMultiLayout<Field>& lay, const PackedLayer<Field>& w,
                    const PackedLayer<Field>& pub,
                    Links<Field> links) const {
    const auto extra = links.resolve(lay);
    ZkMultiProof<Field> proof(lay, kRate, kQueries);
    ZkMultiProver<Field, typename Env::RS::Factory> prover(lay, env_.f,
                                                            env_.factory());
    SecureRandomEngine rng;
    Transcript tp((uint8_t*)"sponge", 6);
    prover.commit(proof, {&w}, tp, rng);
    if (!prover.prove(proof, {&w}, tp, extra)) return false;
    std::vector<uint8_t> bytes;
    proof.write(bytes, env_.f);
    ZkMultiProof<Field> got(lay, kRate, kQueries);
    ReadBuffer rb(bytes);
    if (!got.read(rb, env_.f)) return false;
    ZkMultiVerifier<Field, typename Env::RS::Factory> verifier(
        lay, env_.factory(), kRate, kQueries, env_.f);
    Transcript tv((uint8_t*)"sponge", 6);
    verifier.recv_commitment(got, tv);
    return verifier.verify(got, {&pub}, tv, extra);
  }

  const Env env_;
};

using Envs = ::testing::Types<Gf2, Fq12>;
TYPED_TEST_SUITE(SpongeProof, Envs);

TYPED_TEST(SpongeProof, ProvesAndVerifies) {
  set_log_level(ERROR);
  EXPECT_TRUE(this->run(false));
}

TYPED_TEST(SpongeProof, RejectsBrokenLink) {
  set_log_level(ERROR);
  EXPECT_FALSE(this->run(true));
}

}  // namespace
}  // namespace pq_cred
}  // namespace proofs
