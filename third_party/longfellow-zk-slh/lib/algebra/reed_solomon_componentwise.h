// Reed-Solomon encoding over an extension field whose evaluation points lie
// in the base field (not upstream): each of the kDegree base coordinates of
// the message is encoded with the base-field code. This generalizes
// ReedSolomonExtension6 to any extension with the interface of Fp24Ext or
// GF2_128Ext (kDegree, BaseField, Elt::e).

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_REED_SOLOMON_COMPONENTWISE_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_REED_SOLOMON_COMPONENTWISE_H_

#include <stddef.h>

#include <memory>
#include <utility>
#include <vector>

#include "util/panic.h"

namespace proofs {

template <class ExtField, class BaseRSFactory>
class ComponentwiseReedSolomon {
  using Elt = typename ExtField::Elt;
  using BaseElt = typename ExtField::BaseField::Elt;
  using BaseRS = typename decltype(std::declval<const BaseRSFactory&>().make(
      1, 1))::element_type;

 public:
  // N points go in, M points come out (including the N points).
  ComponentwiseReedSolomon(size_t n, size_t m, const BaseRSFactory& base)
      : n_(n), m_(m), rs_(base.make(n, m)), t_(m) {}

  // Given Y[0, N), fills Y[N, M). Not thread safe: uses one buffer. The code
  // is linear: a coordinate that is zero in Y[0, N) (the coordinates 1 to
  // kDegree - 1 of a message in the base field) is zero in Y[N, M), without
  // encoding.
  void interpolate(Elt y[/*m*/]) const {
    const BaseElt zero{};  // Fp24 and GF2_128 elements start at zero
    for (size_t d = 0; d < ExtField::kDegree; ++d) {
      bool is_zero = true;
      for (size_t i = 0; i < n_; ++i) {
        t_[i] = y[i].e[d];
        is_zero &= t_[i] == zero;
      }
      if (is_zero) {
        for (size_t i = n_; i < m_; ++i) y[i].e[d] = zero;
        continue;
      }
      rs_->interpolate(&t_[0]);
      for (size_t i = n_; i < m_; ++i) y[i].e[d] = t_[i];
    }
  }

  // interpolate() at the outputs POS[t] (n <= POS[t] < m) only, into OUT[t]
  // (not upstream), when the base code is that of ReedSolomon (binom(),
  // leading(), inverse()): OUT[t] = leading(k) sum_j binom(j) Y[j]
  // inverse(k - j) for k = POS[t], about NPOS N products by base elements
  // summed before their reduction (ExtField::Acc), instead of an encoding of
  // every coordinate (ExtField::mac_backward). The same values.
  template <class B = BaseRS,
            class = decltype(std::declval<const B&>().binom(0)),
            class E = ExtField, class = decltype(std::declval<const E&>().acc())>
  void interpolate_at(const Elt y[/*n*/], size_t npos, const size_t pos[],
                      Elt out[/*npos*/], const ExtField& F) const {
    std::vector<Elt> x(n_);
    for (size_t j = 0; j < n_; ++j) x[j] = F.mulf(y[j], rs_->binom(j));
    for (size_t t = 0; t < npos; ++t) {
      const size_t k = pos[t];
      check(k >= n_ && k < m_, "interpolate_at: position out of range");
      auto acc = F.acc();
      F.mac_backward(acc, &x[0], &rs_->inverse(k), n_);
      out[t] = F.mulf(F.reduce(acc), rs_->leading(k));
    }
  }

 private:
  const size_t n_, m_;
  const decltype(std::declval<const BaseRSFactory&>().make(1, 1)) rs_;
  mutable std::vector<BaseElt> t_;
};

template <class ExtField, class BaseRSFactory>
class ComponentwiseReedSolomonFactory {
 public:
  explicit ComponentwiseReedSolomonFactory(const BaseRSFactory& base)
      : base_(base) {}

  std::unique_ptr<ComponentwiseReedSolomon<ExtField, BaseRSFactory>> make(
      size_t n, size_t m) const {
    return std::make_unique<ComponentwiseReedSolomon<ExtField, BaseRSFactory>>(
        n, m, base_);
  }

 private:
  const BaseRSFactory& base_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_REED_SOLOMON_COMPONENTWISE_H_
