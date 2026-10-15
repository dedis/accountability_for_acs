// ZK proofs of two different circuits over one commitment, linked by extra
// linear constraints (zk/zk_multi.h), over GF(2^256) and Fq^12.
//
// Part 0 has NC copies; each has a public byte A and private bytes X, Y,
// and asserts Y = (X AND A) XOR X. Part 1 has one copy with private bytes
// U, V and asserts V = NOT U. The links: X of copy c + 1 of part 0 = Y of
// copy c, and U of part 1 = Y of the last copy of part 0.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/fp24_ext.h"
#include "arrays/packed_layer.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_zk_harness.h"
#include "circuits/tests/pq/slh_dsa/slh_dsa_zk.h"
#include "gf2k/gf2_128_ext.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_multi.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

constexpr size_t kRate = 4;
constexpr size_t kQueries = 128;
// Part 0 inputs: one, A (1-8); private X (9-16), Y (17-24).
constexpr size_t kA = 1, kX = 9, kY = 17;
// Part 1 inputs: one; private U (1-8), V (9-16).
constexpr size_t kU = 1, kV = 9;

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
class ZkMultiTest : public ::testing::Test {
 protected:
  using Field = typename Env::Field;
  using Extra = typename ZkCommon<Field>::ExtraConstraints;
  using LC = Logic<Field, CompilerBackend<Field>>;

  struct Instance {
    std::vector<uint8_t> a, x, y;
    uint8_t u, v;
  };

  static Instance make_instance(size_t nc) {
    Instance in;
    uint8_t x = 0xA5;
    for (size_t c = 0; c < nc; ++c) {
      const uint8_t a = static_cast<uint8_t>(0x3C + 17 * c);
      const uint8_t y = static_cast<uint8_t>((x & a) ^ x);
      in.a.push_back(a);
      in.x.push_back(x);
      in.y.push_back(y);
      x = y;
    }
    in.u = x;
    in.v = static_cast<uint8_t>(~x);
    return in;
  }

  std::unique_ptr<Circuit<Field>> part0(size_t nc) const {
    QuadCircuit<Field> Q(env_.f);
    const CompilerBackend<Field> cbk(&Q);
    const LC L(&cbk, env_.f);
    auto a = L.template vinput<8>();
    Q.private_input();
    auto x = L.template vinput<8>();
    auto y = L.template vinput<8>();
    Q.begin_full_field();
    L.vassert_eq(y, L.vxor(L.vand(x, a), x));
    return Q.mkcircuit(nc);
  }

  std::unique_ptr<Circuit<Field>> part1() const {
    QuadCircuit<Field> Q(env_.f);
    const CompilerBackend<Field> cbk(&Q);
    const LC L(&cbk, env_.f);
    Q.private_input();
    auto u = L.template vinput<8>();
    auto v = L.template vinput<8>();
    Q.begin_full_field();
    L.vassert_eq(v, L.vnot(u));
    return Q.mkcircuit(1);
  }

  static void set_byte(PackedLayer<Field>& w, size_t i, size_t c, uint8_t x) {
    for (size_t b = 0; b < 8; ++b) w.set_bit(i + b, c, (x >> b) & 1);
  }

  // Inputs of part 0 and part 1; with PUBLIC_ONLY, only the public inputs.
  void fill(const Instance& in, bool public_only, PackedLayer<Field>& w0,
            PackedLayer<Field>& w1) const {
    for (size_t c = 0; c < in.a.size(); ++c) {
      w0.set_bit(0, c, true);
      set_byte(w0, kA, c, in.a[c]);
      if (!public_only) {
        set_byte(w0, kX, c, in.x[c]);
        set_byte(w0, kY, c, in.y[c]);
      }
    }
    w1.set_bit(0, 0, true);
    if (!public_only) {
      set_byte(w1, kU, 0, in.u);
      set_byte(w1, kV, 0, in.v);
    }
  }

  static Extra links(const ZkMultiLayout<Field>& lay, const Field& f) {
    Extra e;
    const size_t nc = lay.circuit(0).nc;
    auto eq = [&](size_t i, size_t j) {
      e.a.push_back(LigeroUnitTerm{uint32_t(e.b.size()), uint32_t(i), false});
      e.a.push_back(LigeroUnitTerm{uint32_t(e.b.size()), uint32_t(j), true});
      e.b.push_back(f.zero());
    };
    for (size_t b = 0; b < 8; ++b) {
      for (size_t c = 0; c + 1 < nc; ++c) {
        eq(lay.index(0, kX + b, c + 1), lay.index(0, kY + b, c));
      }
      eq(lay.index(1, kU + b, 0), lay.index(0, kY + b, nc - 1));
    }
    return e;
  }

  struct Run {
    std::unique_ptr<Circuit<Field>> c0, c1;
    std::unique_ptr<ZkMultiLayout<Field>> lay;
    std::vector<uint8_t> bytes;
    bool proved = false;
  };

  Run prove(const Instance& in) const {
    Run r;
    r.c0 = part0(in.a.size());
    r.c1 = part1();
    r.lay = std::make_unique<ZkMultiLayout<Field>>(
        std::vector<const Circuit<Field>*>{r.c0.get(), r.c1.get()});
    PackedLayer<Field> w0(r.c0->nc, r.c0->ninputs, env_.f);
    PackedLayer<Field> w1(1, r.c1->ninputs, env_.f);
    fill(in, false, w0, w1);
    const std::vector<const PackedLayer<Field>*> w{&w0, &w1};
    ZkMultiProof<Field> proof(*r.lay, kRate, kQueries);
    ZkMultiProver<Field, typename Env::RS::Factory> prover(*r.lay, env_.f,
                                                            env_.factory());
    SecureRandomEngine rng;
    Transcript tp((uint8_t*)"multi", 5);
    prover.commit(proof, w, tp, rng);
    r.proved = prover.prove(proof, w, tp, links(*r.lay, env_.f));
    proof.write(r.bytes, env_.f);
    return r;
  }

  bool verify(const Run& r, const Instance& in, const Extra& extra) const {
    ZkMultiProof<Field> proof(*r.lay, kRate, kQueries);
    ReadBuffer rb(r.bytes);
    if (!proof.read(rb, env_.f)) return false;
    PackedLayer<Field> p0(r.c0->nc, r.c0->npub_in, env_.f);
    PackedLayer<Field> p1(1, r.c1->npub_in, env_.f);
    fill(in, true, p0, p1);
    ZkMultiVerifier<Field, typename Env::RS::Factory> verifier(
        *r.lay, env_.factory(), kRate, kQueries, env_.f);
    Transcript tv((uint8_t*)"multi", 5);
    verifier.recv_commitment(proof, tv);
    return verifier.verify(proof, {&p0, &p1}, tv, extra);
  }

  const Env env_;
};

using Envs = ::testing::Types<Gf2, Fq12>;
TYPED_TEST_SUITE(ZkMultiTest, Envs);

TYPED_TEST(ZkMultiTest, ProvesAndVerifies) {
  set_log_level(ERROR);
  for (size_t nc : {1, 3, 5}) {
    const auto in = this->make_instance(nc);
    const auto r = this->prove(in);
    ASSERT_TRUE(r.proved) << "nc=" << nc;
    EXPECT_TRUE(this->verify(r, in, this->links(*r.lay, this->env_.f)))
        << "nc=" << nc;
  }
}

TYPED_TEST(ZkMultiTest, RejectsChangedPublicInput) {
  set_log_level(ERROR);
  const auto in = this->make_instance(3);
  const auto r = this->prove(in);
  ASSERT_TRUE(r.proved);
  auto bad = in;
  bad.a[1] ^= 0x10;
  EXPECT_FALSE(this->verify(r, bad, this->links(*r.lay, this->env_.f)));
}

TYPED_TEST(ZkMultiTest, RejectsBrokenLinkBetweenParts) {
  set_log_level(ERROR);
  // Each part holds alone, but U is not Y of the last copy of part 0.
  auto in = this->make_instance(3);
  in.u ^= 0x01;
  in.v = static_cast<uint8_t>(~in.u);
  const auto r = this->prove(in);
  EXPECT_FALSE(this->verify(r, in, this->links(*r.lay, this->env_.f)));
}

TYPED_TEST(ZkMultiTest, RejectsOtherStatement) {
  set_log_level(ERROR);
  const auto in = this->make_instance(3);
  const auto r = this->prove(in);
  ASSERT_TRUE(r.proved);
  const auto& f = this->env_.f;
  // An extra row that the witness satisfies is another statement.
  auto other = this->links(*r.lay, f);
  other.a.push_back(LigeroUnitTerm{uint32_t(other.b.size()), uint32_t(r.lay->index(0, 9, 0)), false});
  other.b.push_back(f.one());  // bit 0 of X in copy 0 (0xA5)
  EXPECT_FALSE(this->verify(r, in, other));
  // A column outside the private inputs is rejected.
  auto bad = this->links(*r.lay, f);
  bad.a[0].w = r.lay->num_witness();
  EXPECT_FALSE(this->verify(r, in, bad));
}

TYPED_TEST(ZkMultiTest, RejectsChangedProofByte) {
  set_log_level(ERROR);
  const auto in = this->make_instance(3);
  auto r = this->prove(in);
  ASSERT_TRUE(r.proved);
  // A byte of the first sumcheck element (after the 48- or 64-byte root).
  r.bytes[kHashDigestSize + 1] ^= 1;
  EXPECT_FALSE(this->verify(r, in, this->links(*r.lay, this->env_.f)));
}

// Transcript::write_each (not upstream; the public inputs) gives the
// transcript of one write per element, also for no element after a
// challenge, and for more elements than one hash update holds.
TYPED_TEST(ZkMultiTest, TranscriptWriteEach) {
  using Elt = typename TypeParam::Field::Elt;
  const auto& f = this->env_.f;
  Transcript gen((uint8_t*)"gen", 3);
  for (size_t n : {0, 1, 2, 100, 1000}) {
    std::vector<Elt> e(n);
    for (Elt& x : e) x = gen.elt(f);
    Transcript a((uint8_t*)"w", 1), b((uint8_t*)"w", 1);
    uint8_t ca[8], cb[8];
    a.bytes(ca, sizeof(ca));
    b.bytes(cb, sizeof(cb));
    for (const Elt& x : e) a.write(x, f);
    b.write_each(n, [&](size_t i) { return e[i]; }, f);
    uint8_t ra[40], rb[40];
    a.bytes(ra, sizeof(ra));
    b.bytes(rb, sizeof(rb));
    EXPECT_EQ(std::vector<uint8_t>(ra, ra + 40), std::vector<uint8_t>(rb, rb + 40))
        << n;
  }
}

// ZkCommon::extra_hash, hashed by 4 KB, against one update per value.
TYPED_TEST(ZkMultiTest, ExtraHash) {
  using Field = typename TypeParam::Field;
  const auto& f = this->env_.f;
  Transcript gen((uint8_t*)"gen", 3);
  for (size_t n : {0, 1, 300, 5000}) {
    typename ZkCommon<Field>::ExtraConstraints e;
    for (size_t k = 0; k < n; ++k) {
      e.a.push_back(LigeroUnitTerm{static_cast<uint32_t>(k / 2),
                                   static_cast<uint32_t>(7 * k + 1),
                                   k % 3 == 0});
    }
    for (size_t k = 0; k < (n + 1) / 2; ++k) e.b.push_back(gen.elt(f));
    Hash h;
    h.Update8(e.a.size());
    h.Update8(e.b.size());
    for (const auto& t : e.a) {
      h.Update8(t.c);
      h.Update8(t.w);
      const uint8_t neg = t.neg;
      h.Update(&neg, 1);
    }
    for (const auto& x : e.b) {
      uint8_t buf[Field::kBytes];
      f.to_bytes_field(buf, x);
      h.Update(buf, sizeof(buf));
    }
    LigeroHash want;
    h.DigestData(want.bytes);
    const LigeroHash got = ZkCommon<Field>::extra_hash(e, f);
    EXPECT_EQ(std::vector<uint8_t>(got.bytes, got.bytes + LigeroHash::kLength),
              std::vector<uint8_t>(want.bytes, want.bytes + LigeroHash::kLength))
        << n;
  }
}

}  // namespace
}  // namespace proofs
