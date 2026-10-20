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

#include <array>
#include <chrono>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <vector>

#include "circuits/tests/pq/credential/credential.h"
#include "circuits/tests/pq/credential/lwe.h"
#include "circuits/tests/pq/credential/ml_dsa_cred.h"
#include "circuits/tests/pq/credential/ossl_sig.h"
#include "circuits/tests/pq/credential/slh_dsa_cred.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
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
  }

  // A new presentation: the nonce or the C4 tag, signed, and the CFT
  // encryption.
  void Refresh() {
    if (kCft) {
      rng_.bytes(show_.t.data(), 32);
      rng_.bytes(sec_.r2.data(), 32);
      std::vector<uint8_t> tr(show_.t.begin(), show_.t.end());
      tr.insert(tr.end(), sec_.r2.begin(), sec_.r2.end());
      show_.c4 = user_.sign(shake256(tr, kHashDigestSize));
      sec_.user_sig = show_.c4;
      std::array<uint8_t, kLweMsgBytes> m;
      std::copy(id_.begin(), id_.end(), m.begin());
      std::copy(sec_.r2.begin(), sec_.r2.end(), m.begin() + kIdBytes);
      show_.ct = Lwe<LP>::encrypt(lwe_pub_, m, rng_, sec_.rnd);
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
  bool Verify() const { return cred_->Verify(show_); }
  size_t ProofBytes() const { return cred_->ProofBytes(); }
  const Cred& cred() const { return *cred_; }
  typename Cred::Show& show() { return show_; }
  typename Cred::Secret& secret() { return sec_; }
  const LweSecret<LP>& lwe_secret() const { return lwe_sec_; }
  const std::vector<uint8_t>& id() const { return id_; }

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
  }

  void Refresh() {
    if (kCft) {
      rng_.bytes(show_.t.data(), 32);
      rng_.bytes(sec_.r2.data(), 32);
      rng_.bytes(sec_.salt.data(), sec_.salt.size());
      std::vector<uint8_t> tr(show_.t.begin(), show_.t.end());
      tr.insert(tr.end(), sec_.r2.begin(), sec_.r2.end());
      show_.c4 = user_.sign(shake256(tr, kHashDigestSize));
      std::array<uint8_t, kLweMsgBytes> m;
      std::copy(id_.begin(), id_.end(), m.begin());
      std::copy(sec_.r2.begin(), sec_.r2.end(), m.begin() + kIdBytes);
      show_.ct = Lwe<LP>::encrypt(lwe_pub_, m, rng_, sec_.rnd);
      show_.h = Cred::binding(id_, sec_.r2, sec_.salt);
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
  bool Verify() const { return cred_->Verify(show_); }
  size_t ProofBytes() const { return cred_->ProofBytes(); }
  typename Cred::Show& show() { return show_; }
  typename Cred::Secret& secret() { return sec_; }

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
  EXPECT_TRUE(h.Verify());
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
  // The authorities decrypt ID || R2.
  const auto m = Lwe<typename MlDsaCredential<MlDsaP, true>::LP>::decrypt(
      h.lwe_secret(), h.show().ct);
  EXPECT_TRUE(std::equal(h.id().begin(), h.id().end(), m.begin()));
  const auto show = h.show();
  h.show().ct.v[0][0] = (h.show().ct.v[0][0] + 1) % ml_dsa::Q;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  h.show().t[0] ^= 1;
  EXPECT_FALSE(h.Verify());
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
  h.show().c4[10] ^= 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  h.show().h[0] ^= 1;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  h.show().ct.u[0][0] = (h.show().ct.u[0][0] + 1) % ml_dsa::Q;
  EXPECT_FALSE(h.Verify());
  h.show() = show;
  EXPECT_TRUE(h.Verify());
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
