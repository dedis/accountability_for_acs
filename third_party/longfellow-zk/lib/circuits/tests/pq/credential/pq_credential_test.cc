// Post-quantum credential proofs (ml_dsa_cred.h, slh_dsa_cred.h): tests
// and the Combined prove/verify benchmarks of Table IV, without and with
// CFT. The program is built twice: pq_credential_test (48-byte digests:
// ML-DSA-65, SLH-DSA-SHAKE-192s and 192f) and pq_credential_5_test
// (64-byte digests: ML-DSA-87, SLH-DSA-SHAKE-256s and 256f).
//
// A benchmark repetition is one presentation: the per-show signing (the
// nonce, or C4) and encryption, then the proof, timed as prove_ns; the
// verification of the serialized proof, timed as verify_ns. The
// credential, the keys and the circuits are made once (issuance).

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "algebra/fp24_ext.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/credential/credential.h"
#include "circuits/tests/pq/credential/lwe.h"
#include "circuits/tests/pq/credential/ml_dsa_cred.h"
#include "circuits/tests/pq/credential/ossl_sig.h"
#include "circuits/tests/pq/credential/slh_dsa_cred.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/crypto.h"
#include "util/log.h"
#include "util/panic.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace pq_cred {
namespace {

constexpr bool kCategory5 = kHashDigestSize == 64;
using MlDsaP =
    std::conditional_t<kCategory5, ml_dsa::MLDsa87Params, ml_dsa::MLDsa65Params>;
constexpr const char* kMlDsaName = kCategory5 ? "ML-DSA-87" : "ML-DSA-65";
using SlhS = std::conditional_t<kCategory5, slh_dsa::SlhDsaShake256s,
                                slh_dsa::SlhDsaShake192s>;
using SlhF = std::conditional_t<kCategory5, slh_dsa::SlhDsaShake256f,
                                slh_dsa::SlhDsaShake192f>;
constexpr const char* kSlhSName =
    kCategory5 ? "SLH-DSA-SHAKE-256s" : "SLH-DSA-SHAKE-192s";
constexpr const char* kSlhFName =
    kCategory5 ? "SLH-DSA-SHAKE-256f" : "SLH-DSA-SHAKE-192f";

Timestamps timestamps() {
  constexpr uint64_t kDay = 24 * 3600 * 1000ull, kYear = 365 * kDay;
  const uint64_t now = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  return Timestamps{now, now - 18 * kYear, now - 30 * kYear, now - kDay,
                    now + kYear};
}

template <class Params, bool kCft>
class MlDsaHarness {
  using Cred = MlDsaCredential<Params, kCft>;
  using LP = typename Cred::LP;

 public:
  MlDsaHarness() : issuer_(kMlDsaName), user_(kMlDsaName) {
    // One fixed key of the CFT authority, so that its encryption circuit
    // is compiled once (circuit_cache.h).
    Transcript authority((uint8_t*)"cft authority", 13);
    Lwe<LP>::keygen(std::array<uint8_t, 32>{}, authority, lwe_pub_, lwe_sec_);
    cred_ = std::make_unique<Cred>(lwe_pub_);
    const Timestamps ts = timestamps();
    id_ = shake256(user_.pk(), kIdBytes);
    sec_.cred = Credential::make(ts, id_, kCft, rng_);
    sec_.ts = ts;
    sec_.issuer_sig = issuer_.sign(sec_.cred.digest());
    sec_.user_pk = user_.pk();
    show_.issuer_pk = issuer_.pk();
    show_.now = ts.now;
    show_.max_birth = ts.max_birth;
    rng_.bytes(show_.verifier.data(), 32);
  }

  // A new presentation: the nonce, or a new request ID and R2 with C4 on
  // SHAKE256(event_tag || R2), and the CFT encryption.
  void Refresh() {
    if (kCft) {
      rng_.bytes(show_.rid.data(), 32);
      rng_.bytes(sec_.r2.data(), 32);
      sec_.user_sig = user_.sign(c4_message(
          event_tag(show_.now, show_.rid, show_.verifier), sec_.r2));
      std::array<uint8_t, kLweMsgBytes> m;
      std::copy(id_.begin(), id_.end(), m.begin());
      std::copy(sec_.r2.begin(), sec_.r2.end(), m.begin() + kIdBytes);
      show_.ct = Lwe<LP>::encrypt(lwe_pub_, m, rng_, sec_.rnd);
      show_.h = cft_binding(id_, sec_.r2);
    } else {
      rng_.bytes(show_.nonce.data(), 32);
      sec_.user_sig = user_.sign(
          std::vector<uint8_t>(show_.nonce.begin(), show_.nonce.end()));
    }
  }

  bool Prove() {
    Refresh();
    return cred_->Prove(show_, sec_);
  }
  // Cheating provers, with CFT.
  //
  // The ciphertext and the LWE witness encrypt another message than the
  // ID || R2 of the sponge. Every circuit holds and only the links between
  // the parts break, which the prover does not check: it proves, and Verify
  // must fail.
  bool ProveAnotherMessage() {
    Refresh();
    std::array<uint8_t, kLweMsgBytes> m;
    rng_.bytes(m.data(), m.size());
    show_.ct = Lwe<LP>::encrypt(lwe_pub_, m, rng_, sec_.rnd);
    sec_.lwe_message_override = m;
    const bool proved = cred_->Prove(show_, sec_);
    sec_.lwe_message_override.reset();
    return proved;
  }
  // C4 under another key (the issuer's), with its own ID in the CFT and H.
  // The credential digest keeps the holder's ID values, so the issuer
  // signature holds; every circuit holds and only the links from the ID
  // attributes to the hash of the C4 key break: it proves, and Verify must
  // fail.
  bool ProveForeignC4() {
    Refresh();
    const std::vector<uint8_t> user_pk = sec_.user_pk;
    sec_.user_pk = issuer_.pk();
    const auto id = shake256(sec_.user_pk, kIdBytes);
    sec_.user_sig = issuer_.sign(c4_message(
        event_tag(show_.now, show_.rid, show_.verifier), sec_.r2));
    std::array<uint8_t, kLweMsgBytes> m;
    std::copy(id.begin(), id.end(), m.begin());
    std::copy(sec_.r2.begin(), sec_.r2.end(), m.begin() + kIdBytes);
    show_.ct = Lwe<LP>::encrypt(lwe_pub_, m, rng_, sec_.rnd);
    show_.h = cft_binding(id, sec_.r2);
    sec_.id_values_from_credential = true;
    const bool proved = cred_->Prove(show_, sec_);
    sec_.id_values_from_credential = false;
    sec_.user_pk = user_pk;
    return proved;
  }
  bool Verify() const { return cred_->Verify(show_); }
  size_t ProofBytes() const { return cred_->ProofBytes(); }
  const Cred& cred() const { return *cred_; }
  typename Cred::Show& show() { return show_; }
  typename Cred::Secret& secret() { return sec_; }
  const std::vector<uint8_t>& id() const { return id_; }
  // The authorities' decryption of the CFT, with the joint key.
  std::array<uint8_t, kLweMsgBytes> Open() const {
    return Lwe<LP>::decrypt(lwe_sec_, show_.ct);
  }

 private:
  SecureRandomEngine rng_;
  OsslKey issuer_, user_;
  LwePublic<LP> lwe_pub_;
  LweSecret<LP> lwe_sec_;
  std::unique_ptr<Cred> cred_;
  std::vector<uint8_t> id_;
  typename Cred::Show show_;
  typename Cred::Secret sec_;
};

template <class P, bool kCft>
class SlhHarness {
  using Cred = SlhDsaCredential<P, kCft>;
  using LP = typename Cred::LP;

 public:
  explicit SlhHarness(const char* name) : issuer_(name), user_(name) {
    // One fixed key of the CFT authority, so that its encryption circuit
    // is compiled once (circuit_cache.h).
    Transcript authority((uint8_t*)"cft authority", 13);
    Lwe<LP>::keygen(std::array<uint8_t, 32>{}, authority, lwe_pub_, lwe_sec_);
    cred_ = std::make_unique<Cred>(lwe_pub_);
    const Timestamps ts = timestamps();
    id_ = shake256(user_.pk(), kIdBytes);
    sec_.cred = Credential::make(ts, id_, kCft, rng_);
    sec_.ts = ts;
    sec_.issuer_sig = issuer_.sign(sec_.cred.digest());
    sec_.user_pk = user_.pk();
    show_.issuer_pk = issuer_.pk();
    show_.now = ts.now;
    show_.max_birth = ts.max_birth;
    rng_.bytes(show_.verifier.data(), 32);
  }

  void Refresh() {
    if (kCft) {
      rng_.bytes(show_.rid.data(), 32);
      rng_.bytes(sec_.r2.data(), 32);
      sec_.user_sig = user_.sign(c4_message(
          event_tag(show_.now, show_.rid, show_.verifier), sec_.r2));
      std::array<uint8_t, kLweMsgBytes> m;
      std::copy(id_.begin(), id_.end(), m.begin());
      std::copy(sec_.r2.begin(), sec_.r2.end(), m.begin() + kIdBytes);
      show_.ct = Lwe<LP>::encrypt(lwe_pub_, m, rng_, sec_.rnd);
      show_.h = cft_binding(id_, sec_.r2);
    } else {
      rng_.bytes(show_.nonce.data(), 32);
      sec_.user_sig = user_.sign(
          std::vector<uint8_t>(show_.nonce.begin(), show_.nonce.end()));
    }
  }

  bool Prove() {
    Refresh();
    return cred_->Prove(show_, sec_);
  }
  // Cheating provers, with CFT.
  //
  // The ciphertext and the LWE witness encrypt another message than the
  // ID || R2 of the sponge. Every circuit holds and only the links between
  // the parts break, which the prover does not check: it proves, and Verify
  // must fail.
  bool ProveAnotherMessage() {
    Refresh();
    std::array<uint8_t, kLweMsgBytes> m;
    rng_.bytes(m.data(), m.size());
    show_.ct = Lwe<LP>::encrypt(lwe_pub_, m, rng_, sec_.rnd);
    sec_.lwe_message_override = m;
    const bool proved = cred_->Prove(show_, sec_);
    sec_.lwe_message_override.reset();
    return proved;
  }
  // C4 under another key (the issuer's), with its own ID in the CFT and H.
  // The credential digest keeps the holder's ID values, so the issuer
  // signature holds; every circuit holds and only the links from the ID
  // attributes to the hash of the C4 key break: it proves, and Verify must
  // fail.
  bool ProveForeignC4() {
    Refresh();
    const std::vector<uint8_t> user_pk = sec_.user_pk;
    sec_.user_pk = issuer_.pk();
    const auto id = shake256(sec_.user_pk, kIdBytes);
    sec_.user_sig = issuer_.sign(c4_message(
        event_tag(show_.now, show_.rid, show_.verifier), sec_.r2));
    std::array<uint8_t, kLweMsgBytes> m;
    std::copy(id.begin(), id.end(), m.begin());
    std::copy(sec_.r2.begin(), sec_.r2.end(), m.begin() + kIdBytes);
    show_.ct = Lwe<LP>::encrypt(lwe_pub_, m, rng_, sec_.rnd);
    show_.h = cft_binding(id, sec_.r2);
    sec_.id_values_from_credential = true;
    const bool proved = cred_->Prove(show_, sec_);
    sec_.id_values_from_credential = false;
    sec_.user_pk = user_pk;
    return proved;
  }
  bool Verify() const { return cred_->Verify(show_); }
  size_t ProofBytes() const { return cred_->ProofBytes(); }
  typename Cred::Show& show() { return show_; }
  typename Cred::Secret& secret() { return sec_; }
  const std::vector<uint8_t>& id() const { return id_; }
  // The authorities' decryption of the CFT, with the joint key.
  std::array<uint8_t, kLweMsgBytes> Open() const {
    return Lwe<LP>::decrypt(lwe_sec_, show_.ct);
  }

 private:
  SecureRandomEngine rng_;
  OsslKey issuer_, user_;
  LwePublic<LP> lwe_pub_;
  LweSecret<LP> lwe_sec_;
  std::unique_ptr<Cred> cred_;
  std::vector<uint8_t> id_;
  typename Cred::Show show_;
  typename Cred::Secret sec_;
};

template <class P, bool kCft>
struct SlhS_ : SlhHarness<P, kCft> {
  SlhS_() : SlhHarness<P, kCft>(kSlhSName) {}
};
template <class P, bool kCft>
struct SlhF_ : SlhHarness<P, kCft> {
  SlhF_() : SlhHarness<P, kCft>(kSlhFName) {}
};

TEST(Lwe, DecryptsTheMessage) {
  using LP = std::conditional_t<kCategory5, LweCategory5, LweCategory3>;
  SecureRandomEngine rng;
  std::array<uint8_t, 32> seed{};
  LwePublic<LP> pub;
  LweSecret<LP> sec;
  Lwe<LP>::keygen(seed, rng, pub, sec);
  std::array<uint8_t, kLweMsgBytes> m;
  rng.bytes(m.data(), m.size());
  LweRandomness<LP> rnd;
  const auto ct = Lwe<LP>::encrypt(pub, m, rng, rnd);
  EXPECT_EQ(Lwe<LP>::decrypt(sec, ct), m);
}

// SHAKE128(0x4b^32 || LABEL), N bytes: the inputs of the known answer of
// crates/pqc/src/lwe.rs (matches_the_known_answer).
std::vector<uint8_t> KatBytes(std::vector<uint8_t> label, size_t n) {
  std::vector<uint8_t> in(32, 0x4b);
  in.insert(in.end(), label.begin(), label.end());
  std::vector<uint8_t> out(n);
  Sha3Reference::shake128Hash(in.data(), in.size(), out.data(), n);
  return out;
}

// N small coefficients: byte b gives b % (2 eta + 1) - eta, modulo q.
template <class LP>
std::vector<uint32_t> KatSmall(std::vector<uint8_t> label, size_t n) {
  std::vector<uint32_t> c;
  for (uint8_t b : KatBytes(std::move(label), n)) {
    c.push_back((b % (2 * LP::eta + 1) + ml_dsa::Q - LP::eta) % ml_dsa::Q);
  }
  return c;
}

// The Rust implementation (crates/pqc/src/lwe.rs) and this reference give
// the same ciphertext for the same inputs, and the encryption circuit
// accepts it. testdata/lwe_kat_<category>.txt holds the Rust U and V.
TEST(Lwe, MatchesTheRustKnownAnswer) {
  using LP = std::conditional_t<kCategory5, LweCategory5, LweCategory3>;
  constexpr size_t K = LP::K, N = ml_dsa::N, Q = ml_dsa::Q;
  const std::array<uint8_t, 32> seed = [] {
    std::array<uint8_t, 32> s;
    s.fill(0x4b);
    return s;
  }();

  // The joint secret and error: the sums of the three authorities' ones.
  LweSecret<LP> sec{};
  std::array<std::array<Poly, K>, kLweSlots> e{};
  for (uint8_t i = 0; i < 3; ++i) {
    const auto s_i = KatSmall<LP>({'s', i}, kLweSlots * K * N);
    const auto e_i = KatSmall<LP>({'e', i}, kLweSlots * K * N);
    for (size_t x = 0; x < kLweSlots * K * N; ++x) {
      uint32_t& sx = sec.s[x / (K * N)][x / N % K][x % N];
      uint32_t& ex = e[x / (K * N)][x / N % K][x % N];
      sx = (sx + s_i[x]) % Q;
      ex = (ex + e_i[x]) % Q;
    }
  }
  LwePublic<LP> pub;
  Lwe<LP>::keygen(seed, sec, e, pub);

  std::array<uint8_t, kLweMsgBytes> m;
  const auto mb = KatBytes({'m'}, kLweMsgBytes);
  std::copy(mb.begin(), mb.end(), m.begin());
  LweRandomness<LP> rnd;
  const auto r = KatSmall<LP>({'r'}, K * N), e1 = KatSmall<LP>({'e', '1'}, K * N),
             e2 = KatSmall<LP>({'e', '2'}, kLweSlots * N);
  for (size_t x = 0; x < K * N; ++x) {
    rnd.r[x / N][x % N] = r[x];
    rnd.e1[x / N][x % N] = e1[x];
  }
  for (size_t x = 0; x < kLweSlots * N; ++x) rnd.e2[x / N][x % N] = e2[x];
  const LweCiphertext<LP> ct = Lwe<LP>::encrypt(pub, m, rnd);

  const std::string path = std::string(PQ_CRED_TESTDATA) + "/lwe_kat_" +
                           (kCategory5 ? "5" : "3") + ".txt";
  std::ifstream kat(path);
  ASSERT_TRUE(kat) << path;
  std::string name;
  uint32_t x;
  ASSERT_TRUE(kat >> name && name == "u") << path;
  for (size_t i = 0; i < K * N; ++i) {
    ASSERT_TRUE(kat >> x) << path;
    EXPECT_EQ(ct.u[i / N][i % N], x) << "U coefficient " << i;
  }
  ASSERT_TRUE(kat >> name && name == "v") << path;
  for (size_t i = 0; i < kLweSlots * N; ++i) {
    ASSERT_TRUE(kat >> x) << path;
    EXPECT_EQ(ct.v[i / N][i % N], x) << "V coefficient " << i;
  }
  // The commitments follow; lwe.h has none.
  ASSERT_TRUE(kat >> name && name == "commitments") << path;
  EXPECT_EQ(Lwe<LP>::decrypt(sec, ct), m);

  // The encryption circuit, evaluated on the ciphertext and the randomness.
  using Field = Fp24Ext<12>;
  using Backend = EvaluationBackend<Field>;
  using Lwec = LweCircuit<Logic<Field, Backend>, LP>;
  const Field f(ml_dsa::Fq(), 7);
  const Backend backend(f, /*panic_on_assertion_failure=*/false);
  const Logic<Field, Backend> lc(&backend, f);
  const auto elt = [&](uint32_t v) { return lc.konst(f.of_scalar(v)); };
  typename Lwec::Public u;
  typename Lwec::Private w;
  for (size_t i = 0; i < K * N; ++i) {
    u.u[i / N][i % N] = elt(ct.u[i / N][i % N]);
    w.r[i / N][i % N] = elt(rnd.r[i / N][i % N]);
    w.e1[i / N][i % N] = elt(rnd.e1[i / N][i % N]);
  }
  for (size_t i = 0; i < kLweSlots * N; ++i) {
    u.v[i / N][i % N] = elt(ct.v[i / N][i % N]);
    w.e2[i / N][i % N] = elt(rnd.e2[i / N][i % N]);
  }
  for (size_t b = 0; b < 8 * kLweMsgBytes; ++b) {
    w.m[b] = lc.bit((m[b / 8] >> (b % 8)) & 1);
  }
  const Lwec circuit(lc, pub);
  circuit.assert_encryption(u, w);
  EXPECT_FALSE(backend.assertion_failed());
  u.v[0][0] = elt((ct.v[0][0] + 1) % Q);
  circuit.assert_encryption(u, w);
  EXPECT_TRUE(backend.assertion_failed());
}

// The vector of event_tag_matches_the_vector (crates/pqc/src/shake.rs), from
// Python's hashlib.shake_256.
TEST(EventTag, MatchesTheVector) {
  std::array<uint8_t, 32> rid, verifier;
  rid.fill(1);
  verifier.fill(2);
  const std::string want =
      "6ec7fb42c33190e4fa743e81aba1349dc5a787ac42d1885aa7220bea8e222dd9"
      "0836a8c10a2fd01c8b8b2d8037384413"
      "5f25dc356c2b29d64bc25d42547e3fc5";
  std::string got;
  for (uint8_t b : event_tag(1, rid, verifier)) {
    const char* hex = "0123456789abcdef";
    got += hex[b >> 4];
    got += hex[b & 15];
  }
  EXPECT_EQ(got, want.substr(0, 2 * kHashDigestSize));
}

TEST(RejPoly, MatchesReference) {
  using Rej = RejPolyCircuit<Logic<Fp24Ext<12>, CompilerBackend<Fp24Ext<12>>>>;
  for (uint8_t seed = 0; seed < 32; ++seed) {
    std::vector<uint8_t> in(34, seed);
    std::vector<uint8_t> out(3 * Rej::kCand);
    Sha3Reference::shake128Hash(in.data(), in.size(), out.data(), out.size());
    std::array<uint32_t, Rej::kCand> cand;
    std::array<uint8_t, ml_dsa::N> sel;
    std::array<uint32_t, ml_dsa::N> coef;
    ASSERT_TRUE(Rej::witness(out, cand, sel, coef));
    const ml_dsa::Rq want = ml_dsa::RejNTTPoly(in, 5);
    for (size_t j = 0; j < ml_dsa::N; ++j) {
      EXPECT_EQ(coef[j], from_elt(want[j])) << "coefficient " << j;
    }
  }
}

template <class H>
void ProveVerifyAndReject() {
  set_log_level(ERROR);
  H h;
  ASSERT_TRUE(h.Prove());
  EXPECT_TRUE(h.Verify());
  const auto show = h.show();
  // A later NOW than VALID_UNTIL, and an earlier MAX_BIRTH than BIRTH.
  h.show().now = h.secret().ts.valid_until + 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  h.show().max_birth = h.secret().ts.birth - 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  h.show().issuer_pk[5] ^= 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  // A NOW or MAX_BIRTH wider than the age circuit compares: their low bits
  // are valid.
  h.show().now += uint64_t(1) << kTsBits;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  h.show().max_birth += uint64_t(1) << kTsBits;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  EXPECT_TRUE(h.Verify());
}

// With CFT: the authorities decrypt the holder's ID || R2, which matches the
// binding H; a changed H fails; a proof of another message, or of C4 under
// another key, does not verify.
template <class H>
void ExpectOpeningMatchesTheBinding(H& h) {
  const auto m = h.Open();
  const std::vector<uint8_t> id(m.begin(), m.begin() + kIdBytes);
  std::array<uint8_t, 32> r2;
  std::copy(m.begin() + kIdBytes, m.end(), r2.begin());
  EXPECT_EQ(id, h.id());
  EXPECT_EQ(cft_binding(id, r2), h.show().h);
  const auto show = h.show();
  h.show().h[0] ^= 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  ASSERT_TRUE(h.ProveAnotherMessage());
  EXPECT_FALSE(h.Verify());
  ASSERT_TRUE(h.ProveForeignC4());
  EXPECT_FALSE(h.Verify());
}

// C4 signs the event tag: a show does not verify for another request ID,
// verifier or time. Leaves SHOW in H.
template <class H, class Show>
void ExpectBoundToTheRequest(H& h, const Show& show) {
  h.show().rid[0] ^= 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  h.show().verifier[31] ^= 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  h.show().now -= 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
}

TEST(MlDsaCredential, NoCftProvesAndRejects) {
  ProveVerifyAndReject<MlDsaHarness<MlDsaP, false>>();
}

TEST(MlDsaCredential, CftProvesAndRejects) {
  using H = MlDsaHarness<MlDsaP, true>;
  ProveVerifyAndReject<H>();
  set_log_level(ERROR);
  H h;
  ASSERT_TRUE(h.Prove());
  const auto show = h.show();
  h.show().ct.v[0][0] = (h.show().ct.v[0][0] + 1) % ml_dsa::Q;
  EXPECT_FALSE(h.Verify());
  h.show().ct.v[0][0] = ml_dsa::Q;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  ExpectBoundToTheRequest(h, show);
  ExpectOpeningMatchesTheBinding(h);
}

TEST(SlhDsaCredential, NoCftProvesAndRejects) {
  ProveVerifyAndReject<SlhS_<SlhS, false>>();
}

TEST(SlhDsaCredential, CftProvesAndRejects) {
  using H = SlhS_<SlhS, true>;
  ProveVerifyAndReject<H>();
  set_log_level(ERROR);
  H h;
  ASSERT_TRUE(h.Prove());
  const auto show = h.show();
  ExpectBoundToTheRequest(h, show);
  h.show().h[0] ^= 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  h.show().ct.u[0][0] = (h.show().ct.u[0][0] + 1) % ml_dsa::Q;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  EXPECT_TRUE(h.Verify());
  ExpectOpeningMatchesTheBinding(h);
}

template <class P>
void SlhSoundness(const char* name) {
  using LP = typename SlhDsaCredential<P, true>::LP;
  SecureRandomEngine rng;
  LwePublic<LP> pub;
  LweSecret<LP> sec;
  Lwe<LP>::keygen(std::array<uint8_t, 32>{}, rng, pub, sec);
  for (bool cft : {false, true}) {
    const auto all = cft ? SlhDsaCredential<P, true>(pub).Soundness()
                         : SlhDsaCredential<P, false>(pub).Soundness();
    for (const ZkSoundness& s : all) {
      std::printf("%s CFT %d: total %.1f, sumcheck %.1f, proximity %.1f, "
                  "field %.1f, linear %.1f\n",
                  name, int(cft), s.total, s.sumcheck, s.proximity, s.field,
                  s.linear);
      EXPECT_GE(s.total, kCategory5 ? 256.0 : 192.0) << name << " CFT " << cft;
    }
  }
}

TEST(SlhDsaCredential, Soundness) {
  SlhSoundness<SlhS>(kSlhSName);
  SlhSoundness<SlhF>(kSlhFName);
}

TEST(MlDsaCredential, Soundness) {
  using LP = std::conditional_t<kCategory5, LweCategory5, LweCategory3>;
  SecureRandomEngine rng;
  LwePublic<LP> pub;
  LweSecret<LP> sec;
  Lwe<LP>::keygen(std::array<uint8_t, 32>{}, rng, pub, sec);
  for (bool cft : {false, true}) {
    const ZkSoundness s =
        cft ? MlDsaCredential<MlDsaP, true>(pub).Soundness()
            : MlDsaCredential<MlDsaP, false>(pub).Soundness();
    std::printf("%s CFT %d: total %.1f, sumcheck %.1f, proximity %.1f, "
                "field %.1f, linear %.1f\n",
                kMlDsaName, int(cft), s.total, s.sumcheck, s.proximity,
                s.field, s.linear);
    EXPECT_GE(s.total, kCategory5 ? 256.0 : 192.0) << "CFT " << cft;
  }
}

int64_t SteadyNsSince(const std::chrono::steady_clock::time_point& t0) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now() - t0)
      .count();
}

template <class H>
void BM_Combined(benchmark::State& state) {
  set_log_level(ERROR);
  H h;
  for (auto _ : state) {
    const auto t0 = std::chrono::steady_clock::now();
    const bool proved = h.Prove();
    const int64_t prove_ns = SteadyNsSince(t0);
    check(proved, "credential proof failed");
    const auto t1 = std::chrono::steady_clock::now();
    const bool verified = h.Verify();
    const int64_t verify_ns = SteadyNsSince(t1);
    check(verified, "credential proof did not verify");
    state.counters["prove_ns"] = static_cast<double>(prove_ns);
    state.counters["verify_ns"] = static_cast<double>(verify_ns);
    state.counters["proof_bytes"] = static_cast<double>(h.ProofBytes());
  }
}

void BM_Combined_PQCred_MLDSA_NoCft(benchmark::State& state) {
  BM_Combined<MlDsaHarness<MlDsaP, false>>(state);
}
void BM_Combined_PQCred_MLDSA_Cft(benchmark::State& state) {
  BM_Combined<MlDsaHarness<MlDsaP, true>>(state);
}
void BM_Combined_PQCred_SLHs_NoCft(benchmark::State& state) {
  BM_Combined<SlhS_<SlhS, false>>(state);
}
void BM_Combined_PQCred_SLHs_Cft(benchmark::State& state) {
  BM_Combined<SlhS_<SlhS, true>>(state);
}
void BM_Combined_PQCred_SLHf_NoCft(benchmark::State& state) {
  BM_Combined<SlhF_<SlhF, false>>(state);
}
void BM_Combined_PQCred_SLHf_Cft(benchmark::State& state) {
  BM_Combined<SlhF_<SlhF, true>>(state);
}
BENCHMARK(BM_Combined_PQCred_MLDSA_NoCft)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Combined_PQCred_MLDSA_Cft)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Combined_PQCred_SLHs_NoCft)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Combined_PQCred_SLHs_Cft)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Combined_PQCred_SLHf_NoCft)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_Combined_PQCred_SLHf_Cft)->Unit(benchmark::kMillisecond);

}  // namespace
}  // namespace pq_cred
}  // namespace proofs
