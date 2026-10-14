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

namespace proofs {

template <class ExtField, class BaseRSFactory>
class ComponentwiseReedSolomon {
  using Elt = typename ExtField::Elt;
  using BaseElt = typename ExtField::BaseField::Elt;

 public:
  // N points go in, M points come out (including the N points).
  ComponentwiseReedSolomon(size_t n, size_t m, const BaseRSFactory& base)
      : n_(n), m_(m), rs_(base.make(n, m)), t_(m) {}

  // Given Y[0, N), fills Y[N, M). Not thread safe: uses one buffer.
  void interpolate(Elt y[/*m*/]) const {
    for (size_t d = 0; d < ExtField::kDegree; ++d) {
      for (size_t i = 0; i < n_; ++i) t_[i] = y[i].e[d];
      rs_->interpolate(&t_[0]);
      for (size_t i = n_; i < m_; ++i) y[i].e[d] = t_[i];
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
