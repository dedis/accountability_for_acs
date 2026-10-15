// The age and validity check of the credential proofs, over any field (not
// upstream): BIRTH <= MAX_BIRTH and VALID_FROM <= NOW <= VALID_UNTIL, on
// 43-bit timestamps (milliseconds). NOW and MAX_BIRTH are public; the
// other three are private, linked to the credential attributes.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_AGE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_AGE_H_

#include <cstddef>
#include <cstdint>

#include "arrays/packed_layer.h"

namespace proofs {
namespace pq_cred {

constexpr size_t kTsBits = 43;

template <class LogicCircuit>
class AgeCircuit {
  using vts = typename LogicCircuit::template bitvec<kTsBits>;

 public:
  // Private input offsets (LSB first), from the first private input.
  static constexpr size_t kBirth = 0;
  static constexpr size_t kValidFrom = kTsBits;
  static constexpr size_t kValidUntil = 2 * kTsBits;
  static constexpr size_t kNPriv = 3 * kTsBits;
  static constexpr size_t kNPub = 1 + 2 * kTsBits;

  struct Public {
    vts now, max_birth;
    void input(const LogicCircuit& lc) {
      now = lc.template vinput<kTsBits>();
      max_birth = lc.template vinput<kTsBits>();
    }
  };
  struct Private {
    vts birth, valid_from, valid_until;
    void input(const LogicCircuit& lc) {
      birth = lc.template vinput<kTsBits>();
      valid_from = lc.template vinput<kTsBits>();
      valid_until = lc.template vinput<kTsBits>();
    }
  };

  explicit AgeCircuit(const LogicCircuit& lc) : lc_(lc) {}

  void assert_valid(const Public& u, const Private& w) const {
    lc_.assert1(lc_.vleq(w.birth, u.max_birth));
    lc_.assert1(lc_.vleq(w.valid_from, u.now));
    lc_.assert1(lc_.vleq(u.now, w.valid_until));
  }

 private:
  const LogicCircuit& lc_;
};

struct Timestamps {
  uint64_t now, max_birth, birth, valid_from, valid_until;
};

// The inputs of the age part (one copy); the private ones unless
// PUBLIC_ONLY.
template <class Field>
void fill_age(PackedLayer<Field>& w, const Timestamps& ts, bool public_only) {
  size_t i = 0;
  auto put = [&](uint64_t x) {
    for (size_t b = 0; b < kTsBits; ++b) w.set_bit(i++, 0, (x >> b) & 1);
  };
  w.set_bit(i++, 0, true);
  put(ts.now);
  put(ts.max_birth);
  if (public_only) return;
  put(ts.birth);
  put(ts.valid_from);
  put(ts.valid_until);
}

}  // namespace pq_cred
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_AGE_H_
