// Capabilities of the extension fields Fp24Ext and GF2_128Ext used by the
// sumcheck (not upstream): elements by base coordinates, sums of products
// before their reduction, and products by base-field coefficients. Other
// fields take the generic operations.

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_BASE_COORDINATES_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_BASE_COORDINATES_H_

#include <type_traits>
#include <utility>

namespace proofs {

// Extension fields whose elements are coordinates E[0..K) over a base field
// (Field::Scalar, with base_field()): Fp24Ext, GF2_128Ext. An element with
// E[1..K) zero lies in the base field and is stored by E[0] alone.
template <class Field, class = void>
struct BaseCoordinates {
  static constexpr bool kOn = false;
  using Scalar = char;
};
template <class Field>
struct BaseCoordinates<
    Field, std::void_t<typename Field::Scalar,
                       decltype(std::declval<typename Field::Elt&>().e[0]),
                       decltype(std::declval<const Field&>().base_field())>> {
  using Scalar = typename Field::Scalar;
  static constexpr bool kOn = std::is_same_v<
      std::decay_t<decltype(std::declval<typename Field::Elt&>().e[0])>,
      Scalar>;
};

// Sums of products, X Y or X times a base element S: the accumulator of the
// field (Field::Acc: products summed before one reduction) if it has one,
// else sums of reduced products. The same sums.
template <class Field, class = void>
struct MacOf {
  using Elt = typename Field::Elt;
  using Acc = Elt;
  static Acc zero(const Field& F) { return F.zero(); }
  static void mac(Acc& a, const Elt& x, const Elt& y, const Field& F) {
    F.add(a, F.mulf(x, y));
  }
  template <class S>
  static void mac(Acc& a, const Elt& x, const S& s, const Field& F) {
    F.add(a, F.mulf(x, s));
  }
  static Elt reduce(const Acc& a, const Field& F) { return a; }
};
template <class Field>
struct MacOf<Field, std::void_t<typename Field::Acc>> {
  using Elt = typename Field::Elt;
  using Acc = typename Field::Acc;
  static Acc zero(const Field& F) { return F.acc(); }
  static void mac(Acc& a, const Elt& x, const Elt& y, const Field& F) {
    F.mac(a, x, y);
  }
  template <class S>
  static void mac(Acc& a, const Elt& x, const S& s, const Field& F) {
    F.mac(a, x, s);
  }
  static Elt reduce(const Acc& a, const Field& F) { return F.reduce(a); }
};

// V X, by K base multiplications when V lies in the base field of an
// extension of odd characteristic (a circuit constant of the ML-DSA
// circuits over Fq^12). The same element as F.mulf(V, X).
template <class Field>
typename Field::Elt mul_coefficient(const typename Field::Elt& v,
                                    const typename Field::Elt& x,
                                    const Field& F) {
  if constexpr (BaseCoordinates<Field>::kOn && !Field::kCharacteristicTwo) {
    if (F.in_subfield(v)) return F.mulf(x, v.e[0]);
  }
  return F.mulf(v, x);
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_BASE_COORDINATES_H_
