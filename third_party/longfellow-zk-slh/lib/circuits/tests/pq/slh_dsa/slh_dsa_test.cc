// Native tests of the SLH-DSA plan (not upstream): the plan verifies the
// examples like FIPS 205, rejects changed inputs, and its witness satisfies
// its links.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/tests/pq/slh_dsa/slh_dsa.h"
#include "circuits/tests/pq/slh_dsa/slh_dsa_examples.h"
#include "gtest/gtest.h"

namespace proofs {
namespace slh_dsa {
namespace {

// The native witness of PLAN satisfies its links.
template <class P>
void CheckLinks(const Plan<P>& plan) {
  for (const auto& [x, y] : plan.eq) {
    ASSERT_EQ(plan.value(x), plan.value(y))
        << "copy " << x.copy << " off " << x.off << " = copy " << y.copy
        << " off " << y.off;
  }
  for (const auto& [x, v] : plan.fixed) {
    ASSERT_EQ(plan.value(x), v) << "copy " << x.copy << " off " << x.off;
  }
  for (const auto& [x, y, z] : plan.sum) {
    ASSERT_EQ(plan.value(x), plan.value(y) != plan.value(z))
        << "copy " << x.copy << " off " << x.off;
  }
  for (const auto& [xy, v] : plan.sum_fixed) {
    ASSERT_EQ(plan.value(xy.first), plan.value(xy.second) != v)
        << "copy " << xy.first.copy << " off " << xy.first.off;
  }
}

template <class P>
void CheckExample(const Example& ex, size_t want_copies) {
  const Plan<P> plan(ex.pk, ex.ctx, ex.msg, ex.sig);
  EXPECT_TRUE(plan.native_ok);
  EXPECT_EQ(plan.copies.size(), want_copies);
  CheckLinks(plan);

  // The plan with one-block copies (not upstream): the same copies, links
  // satisfied by its witness in both layouts.
  const Plan<P> one(Val::konst(ex.pk.data(), P::n),
                    Val::konst(ex.pk.data() + P::n, P::n), ex.ctx,
                    Val::free(ex.msg.data(), ex.msg.size()), ex.sig,
                    /*sig_public=*/false, /*one_block=*/true);
  EXPECT_TRUE(one.native_ok);
  EXPECT_EQ(one.copies.size(), want_copies);
  CheckLinks(one);

  // Changed signature, message, context or key.
  for (size_t at : {size_t(0), P::n, ex.sig.size() / 2, ex.sig.size() - 1}) {
    std::vector<uint8_t> sig = ex.sig;
    sig[at] ^= 1;
    EXPECT_FALSE((Plan<P>(ex.pk, ex.ctx, ex.msg, sig).native_ok)) << at;
  }
  std::vector<uint8_t> msg = ex.msg;
  msg[0] ^= 1;
  EXPECT_FALSE((Plan<P>(ex.pk, ex.ctx, msg, ex.sig).native_ok));
  std::vector<uint8_t> ctx = ex.ctx;
  ctx.back() ^= 1;
  EXPECT_FALSE((Plan<P>(ex.pk, ctx, ex.msg, ex.sig).native_ok));
  std::vector<uint8_t> pk = ex.pk;
  pk[0] ^= 1;
  EXPECT_FALSE((Plan<P>(pk, ex.ctx, ex.msg, ex.sig).native_ok));

  // Wrong lengths do not verify (FIPS 205 Alg. 24), without aborting.
  pk = ex.pk;
  pk.pop_back();
  EXPECT_FALSE((Plan<P>(pk, ex.ctx, ex.msg, ex.sig).native_ok));
  std::vector<uint8_t> sig = ex.sig;
  sig.push_back(0);
  EXPECT_FALSE((Plan<P>(ex.pk, ex.ctx, ex.msg, sig).native_ok));
  EXPECT_FALSE(
      (Plan<P>(ex.pk, std::vector<uint8_t>(256), ex.msg, ex.sig).native_ok));
}

// Expected copies: H_msg blocks + FORS (k leaves, k*a auth, T_k blocks) +
// d layers of (len chains of 15, T_len blocks, h' auth).
TEST(SlhDsaPlan, Shake192s) { CheckExample<SlhDsaShake192s>(Example192s(), 5748); }
TEST(SlhDsaPlan, Shake192f) { CheckExample<SlhDsaShake192f>(Example192f(), 17421); }
TEST(SlhDsaPlan, Shake256s) { CheckExample<SlhDsaShake256s>(Example256s(), 8578); }
TEST(SlhDsaPlan, Shake256f) { CheckExample<SlhDsaShake256f>(Example256f(), 17803); }

}  // namespace
}  // namespace slh_dsa
}  // namespace proofs
