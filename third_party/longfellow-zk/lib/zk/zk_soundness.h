// Soundness bits of a ZK proof (not upstream): -log2 of the bounds on the
// probability that the verifier accepts a false statement, per component:
//
//   sumcheck:  sum of the round degrees, plus one per random combination
//              (of the two claims and of the assertions of each layer, and
//              of the input binding), over |F| (union bound; Thaler, Proofs,
//              Arguments, and Zero-Knowledge, Prop. 4.1);
//   proximity: C((n + k) / 2, t) / C(n, t), the Ligero code test in the
//              unique-decoding regime (Ligero Inc. security review of
//              Longfellow, Thm 4.3), with k = BLOCK, n = BLOCK_ENC - DBLOCK
//              (the opened positions) and t = NREQ;
//   field:     (n + 1) / |F|, the other term of Thm 4.3;
//   linear:    C(2k - 2, t) / C(n, t) + 1 / |F|, each of the linear and the
//              quadratic test (Thm 4.4).
//
// TOTAL is -log2 of the sum of the bounds. LOG2_FIELD is log2 |F|.

#ifndef PRIVACY_PROOFS_ZK_LIB_ZK_ZK_SOUNDNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_ZK_ZK_SOUNDNESS_H_

#include <cmath>
#include <cstddef>
#include <vector>

#include "ligero/ligero_param.h"
#include "sumcheck/circuit.h"

namespace proofs {

struct ZkSoundness {
  double sumcheck, proximity, field, linear, total;
};

// Proof of the circuits C (several for zk/zk_multi.h) over one commitment
// with Ligero parameters P: the sumcheck terms add up over the circuits.
template <class Field>
ZkSoundness zk_soundness(const std::vector<const Circuit<Field>*>& cs,
                         const LigeroParam<Field>& p, double log2_field) {
  // log2 of the binomial coefficient C(n, k).
  auto lc = [](double n, double k) {
    return (std::lgamma(n + 1) - std::lgamma(k + 1) - std::lgamma(n - k + 1)) /
           std::log(2.0);
  };
  double degrees = 0;
  for (const Circuit<Field>* c : cs) {
    degrees += 1;  // the random combination of the input binding
    for (size_t ly = 0; ly < c->nl; ++ly) {
      degrees += 3.0 * c->logc + 4.0 * c->l[ly].logw + 2;
    }
  }
  const double n = p.block_enc - p.dblock, k = p.block, t = p.nreq;
  const double e_sum = degrees * std::exp2(-log2_field);
  const double e_prox = std::exp2(lc(std::floor((n + k) / 2), t) - lc(n, t));
  const double e_field = (n + 1) * std::exp2(-log2_field);
  const double e_lin =
      std::exp2(lc(2 * k - 2, t) - lc(n, t)) + std::exp2(-log2_field);
  return ZkSoundness{-std::log2(e_sum), -std::log2(e_prox),
                     -std::log2(e_field), -std::log2(e_lin),
                     -std::log2(e_sum + e_prox + e_field + 2 * e_lin)};
}

template <class Field>
ZkSoundness zk_soundness(const Circuit<Field>& c, const LigeroParam<Field>& p,
                         double log2_field) {
  return zk_soundness(std::vector<const Circuit<Field>*>{&c}, p, log2_field);
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ZK_ZK_SOUNDNESS_H_
