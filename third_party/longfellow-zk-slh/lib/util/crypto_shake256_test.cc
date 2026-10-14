// Known-answer tests for the SHAKE256 hash and PRF in util/crypto.h, which the
// pq build (PROOFS_SHAKE256) uses in the proof system. Not upstream. Expected
// values from Python's hashlib.shake_256.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <type_traits>

#include "util/crypto.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

static_assert(std::is_same_v<Hash, SHAKE256>, "build with PROOFS_SHAKE256");
static_assert(std::is_same_v<PRF, ShakePRF>, "build with PROOFS_SHAKE256");
static_assert(kHashDigestSize == 48, "build with PROOFS_SHAKE256");

std::string hex(const uint8_t* b, size_t n) {
  std::string s;
  char buf[3];
  for (size_t i = 0; i < n; ++i) {
    std::snprintf(buf, sizeof(buf), "%02x", b[i]);
    s += buf;
  }
  return s;
}

const uint8_t kAbc[] = {'a', 'b', 'c'};
const char kShakeAbc[] =
    "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef18"
    "6a5386c75744c0527e1faa";

TEST(SHAKE256, KnownAnswer) {
  SHAKE256 h;
  h.Update(kAbc, 3);
  uint8_t d[kSHAKE256DigestSize];
  h.DigestData(d);
  EXPECT_EQ(hex(d, sizeof(d)), kShakeAbc);
}

TEST(SHAKE256, CopyStateForksTheState) {
  SHAKE256 a;
  a.Update(kAbc, 1);
  SHAKE256 b;
  b.CopyState(a);
  a.Update(kAbc + 1, 2);
  b.Update(kAbc + 1, 2);
  uint8_t da[kSHAKE256DigestSize], db[kSHAKE256DigestSize];
  a.DigestData(da);
  b.DigestData(db);
  EXPECT_EQ(hex(da, sizeof(da)), kShakeAbc);
  EXPECT_EQ(hex(db, sizeof(db)), kShakeAbc);
}

TEST(SHAKE256, Update8IsLittleEndian) {
  const uint8_t bytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  SHAKE256 a, b;
  a.Update8(0x0807060504030201);
  b.Update(bytes, 8);
  uint8_t da[kSHAKE256DigestSize], db[kSHAKE256DigestSize];
  a.DigestData(da);
  b.DigestData(db);
  EXPECT_EQ(hex(da, sizeof(da)), hex(db, sizeof(db)));
}

// Eval(in) = SHAKE256(key || in), 136 bytes; key = 00..2f, in = le64(i) || 0^8
// as FSPRF builds it.
TEST(ShakePRF, KnownAnswer) {
  const char* kExpected[] = {
      "01eac8adb0f14f5b14bc5d50ce297f38e4cb360021f368d9c7591c067122f8fdde8c237f"
      "225aa329495c4e2ad1b305ec96f928705588b3169637f691137baf880fe0a3057f7b3202"
      "0c34741af729165179f2b702e18135979fb3922c65492c22879a485e9183c76d245e5bb1"
      "3f3b5db30cf9bf906ca1d84b3378715c6465c7367adcb819ce473c6b",
      "e45dc75b781237a28f047737c4c3454ca2bfee2ed4df7ad11f5f26f67ee6d30161808576"
      "9d0d6da786bd802ec719499f9bc66facf12cb9dc4148c3c3a7e947c7fcb30dac3c3c0338"
      "357dbed777e40574a09932a233592e032d91f666525b97a1e73d73ad69e15b1104806203"
      "98359153a220800da6d6d1e9824a1301d157638369a2b228587b0675",
  };
  uint8_t key[ShakePRF::kKeySize];
  for (size_t i = 0; i < ShakePRF::kKeySize; ++i) key[i] = static_cast<uint8_t>(i);
  ShakePRF prf(key);
  for (uint8_t i = 0; i < 2; ++i) {
    uint8_t in[kPRFInputSize] = {i};
    uint8_t out[ShakePRF::kOutputSize];
    prf.Eval(out, in);
    EXPECT_EQ(hex(out, sizeof(out)), kExpected[i]);
  }
}

}  // namespace
}  // namespace proofs
