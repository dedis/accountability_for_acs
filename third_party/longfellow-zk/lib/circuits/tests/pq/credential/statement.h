// References to private inputs of a multi-circuit proof, and the linear
// constraints between them (not upstream; zk/zk_multi.h).
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!  Experimental research code.
//
// A statement is built before the copy counts of its parts are known, so
// constraints refer to (part, copy, private input) and are resolved to
// indices of the committed vector at the end (Links::resolve).

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_STATEMENT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_STATEMENT_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ligero/ligero_param.h"
#include "util/panic.h"
#include "zk/zk_common.h"
#include "zk/zk_multi.h"

namespace proofs {
namespace pq_cred {

// Private input OFF (counted from the first private input) of copy COPY of
// part PART.
struct Ref {
  uint32_t part, copy, off;
};

// One bit of a value: a constant; a private input that defines the bit
// (FREE: the first use of a secret); or a reference to the private input
// that defines it. VALUE is the native value.
struct Bit {
  enum Kind : uint8_t { kConst, kFree, kRef };
  Kind kind;
  bool value;
  Ref r;

  static Bit konst(bool v) { return Bit{kConst, v, Ref{0, 0, 0}}; }
  static Bit free(bool v) { return Bit{kFree, v, Ref{0, 0, 0}}; }
  static Bit ref(bool v, Ref r) { return Bit{kRef, v, r}; }
};

// A byte string: bit B of byte I is at 8 I + B.
using Bytes = std::vector<Bit>;

inline Bytes const_bytes(const uint8_t* p, size_t len) {
  Bytes v;
  v.reserve(8 * len);
  for (size_t i = 0; i < len; ++i) {
    for (size_t b = 0; b < 8; ++b) v.push_back(Bit::konst((p[i] >> b) & 1));
  }
  return v;
}

inline Bytes free_bytes(const uint8_t* p, size_t len) {
  Bytes v;
  v.reserve(8 * len);
  for (size_t i = 0; i < len; ++i) {
    for (size_t b = 0; b < 8; ++b) v.push_back(Bit::free((p[i] >> b) & 1));
  }
  return v;
}

inline uint8_t byte_of(const Bytes& v, size_t i) {
  uint8_t x = 0;
  for (size_t b = 0; b < 8; ++b) x |= uint8_t(v[8 * i + b].value) << b;
  return x;
}

inline std::vector<uint8_t> values(const Bytes& v) {
  std::vector<uint8_t> r(v.size() / 8);
  for (size_t i = 0; i < r.size(); ++i) r[i] = byte_of(v, i);
  return r;
}

inline Bytes slice(const Bytes& v, size_t off, size_t len) {
  check(8 * (off + len) <= v.size(), "slice out of range");
  return Bytes(v.begin() + 8 * off, v.begin() + 8 * (off + len));
}

inline Bytes cat(std::initializer_list<const Bytes*> parts) {
  size_t n = 0;
  for (const Bytes* p : parts) n += p->size();
  Bytes v;
  v.reserve(n);
  for (const Bytes* p : parts) v.insert(v.end(), p->begin(), p->end());
  return v;
}

// Linear constraints sum_t (+-1) x_t = rhs on private inputs.
template <class Field>
class Links {
  using Elt = typename Field::Elt;

 public:
  explicit Links(const Field& f) : f_(f) {}

  // A == B.
  void eq(const Ref& a, const Ref& b) {
    term(a, false);
    term(b, true);
    end(f_.zero());
  }

  // A == V.
  void fixed(const Ref& a, const Elt& v) {
    term(a, false);
    end(v);
  }

  // Private input A takes bit SRC: nothing for a free bit (A defines it).
  void bit(const Ref& a, const Bit& src) {
    if (src.kind == Bit::kConst) {
      fixed(a, src.value ? f_.one() : f_.zero());
    } else if (src.kind == Bit::kRef) {
      eq(a, src.r);
    }
  }

  // A general row: add terms (+R, or -R if NEG), then end it with its
  // right-hand side.
  void term(const Ref& r, bool neg) {
    t_.push_back(Term{static_cast<uint32_t>(rhs_.size()), neg, r});
  }
  void end(const Elt& rhs) { rhs_.push_back(rhs); }

  size_t rows() const { return rhs_.size(); }

  // The constraints on the committed vector of LAY. Consumes the links:
  // the right-hand sides move, and the terms are freed once converted.
  typename ZkCommon<Field>::ExtraConstraints resolve(
      const ZkMultiLayout<Field>& lay) {
    check(rhs_.size() < (size_t(1) << 32), "too many link rows");
    typename ZkCommon<Field>::ExtraConstraints e;
    e.a.reserve(t_.size());
    for (const Term& t : t_) {
      check(t.r.part < lay.parts(), "link part out of range");
      const auto& c = lay.circuit(t.r.part);
      check(t.r.copy < c.nc && c.npub_in + t.r.off < c.ninputs,
            "link input out of range");
      const size_t w = lay.index(t.r.part, c.npub_in + t.r.off, t.r.copy);
      check(w < (size_t(1) << 32), "witness index above 32 bits");
      e.a.push_back(LigeroUnitTerm{t.row, static_cast<uint32_t>(w), t.neg});
    }
    std::vector<Term>().swap(t_);
    e.b = std::move(rhs_);
    rhs_.clear();
    return e;
  }

 private:
  struct Term {
    uint32_t row;
    bool neg;
    Ref r;
  };
  const Field& f_;
  std::vector<Term> t_;
  std::vector<Elt> rhs_;
};

}  // namespace pq_cred
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_STATEMENT_H_
