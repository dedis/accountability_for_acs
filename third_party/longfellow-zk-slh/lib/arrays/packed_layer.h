// Wires of all copies with each 0/1 wire stored as bits (not upstream).

#ifndef PRIVACY_PROOFS_ZK_LIB_ARRAYS_PACKED_LAYER_H_
#define PRIVACY_PROOFS_ZK_LIB_ARRAYS_PACKED_LAYER_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/affine.h"
#include "arrays/dense.h"
#include "util/panic.h"

namespace proofs {

// The wires of one layer (or the inputs) for all copies, in the layout of
// Dense (copies adjacent: element (c, i) at index n0 * i + c), with each
// wire that is 0 or 1 in every copy stored as one bit per copy. The bits of
// wire I are at word I * words(); the other wires (about 1% in the SLH-DSA
// circuit) are kept in full and leave their bit words zero. Unpacking gives
// the same elements. Packing and unpacking do not branch on the bit values.
template <class Field>
class PackedLayer {
  using Elt = typename Field::Elt;

 public:
  // N1 wires of N0 copies, all bits and zero; set them with set_wire() or
  // set_bit().
  PackedLayer(corner_t n0, corner_t n1, const Field& F)
      : n0_(n0),
        n1_(n1),
        words_((n0 + 63) / 64),
        value_{F.zero(), F.one()},
        full_index_(n1, kBits),
        bits_(n1 * words_, 0) {}

  PackedLayer(const Dense<Field>& d, const Field& F)
      : PackedLayer(d.n0_, d.n1_, F) {
    for (corner_t i = 0; i < n1_; ++i) set_wire(i, &d.v_[n0_ * i]);
  }

  // Stores X[0, n0) as wire I, which must not be set yet. The full wires
  // are appended to one buffer, which grows geometrically.
  void set_wire(corner_t i, const Elt* x) {
    uint64_t* b = &bits_[words_ * i];
    bool is_bits = true;
    for (corner_t c = 0; c < n0_; ++c) {
      const bool is_one = x[c] == value_[1];
      b[c / 64] |= uint64_t(is_one) << (c % 64);
      is_bits &= is_one | (x[c] == value_[0]);
    }
    if (!is_bits) {
      std::fill(b, b + words_, 0);
      check(full_.size() / n0_ < kBits, "too many full wires");
      full_index_[i] = static_cast<uint32_t>(full_.size() / n0_);
      full_.insert(full_.end(), x, x + n0_);
    }
  }

  // Sets wire I of copy C, a bit wire, to BIT, which must be its first
  // assignment.
  void set_bit(corner_t i, corner_t c, bool bit) {
    check(full_index_[i] == kBits && c < n0_, "set_bit: not a bit wire");
    bits_[words_ * i + c / 64] |= uint64_t(bit) << (c % 64);
  }

  corner_t n0() const { return n0_; }
  corner_t n1() const { return n1_; }
  size_t words() const { return words_; }

  // The bits of wire I, or nullptr if wire I is kept in full.
  const uint64_t* bits(corner_t i) const {
    return full_index_[i] == kBits ? &bits_[words_ * i] : nullptr;
  }

  // The elements of wire I, which bits(I) must not hold.
  const Elt* full(corner_t i) const { return &full_[n0_ * full_index_[i]]; }

  // Element J in the layout of Dense: copy J % n0 of wire J / n0.
  Elt at(corner_t j) const {
    const corner_t i = j / n0_, c = j % n0_;
    if (const uint64_t* b = bits(i)) return value_[(b[c / 64] >> (c % 64)) & 1];
    return full(i)[c];
  }

  // Writes the wires into D, whose buffer must be large enough, and gives
  // D the dimensions of the layer.
  void unpack(Dense<Field>& d) const {
    check(d.v_.size() >= n0_ * n1_, "unpack buffer too small");
    d.n0_ = n0_;
    d.n1_ = n1_;
    for (corner_t i = 0; i < n1_; ++i) {
      Elt* x = &d.v_[n0_ * i];
      if (const uint64_t* b = bits(i)) {
        for (corner_t c = 0; c < n0_; ++c) {
          x[c] = value_[(b[c / 64] >> (c % 64)) & 1];
        }
      } else {
        std::copy(full(i), full(i) + n0_, x);
      }
    }
  }

 private:
  static constexpr uint32_t kBits = ~uint32_t(0);
  corner_t n0_, n1_;
  size_t words_;                      // 64-bit words per wire
  Elt value_[2];                      // zero and one
  std::vector<uint32_t> full_index_;  // per wire: kBits, or its full index
  std::vector<uint64_t> bits_;        // [n1_, words_]
  std::vector<Elt> full_;             // [full wires, n0_]
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ARRAYS_PACKED_LAYER_H_
