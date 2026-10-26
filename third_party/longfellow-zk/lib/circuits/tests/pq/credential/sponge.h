// SHAKE128 and SHAKE256 as copies of one Keccak-f step circuit, over any
// field (not upstream).
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!  Experimental research code.
//
// One copy proves one Keccak-f call:
//
//   in    = PUB xor (MASK and DATA)          (168 bytes, the SHAKE128 rate)
//   state = (CONT ? S_IN : 0) xor (in || 0)  (1600 bits)
//   S_OUT = Keccak-f(state)
//
// PUB, MASK and CONT are public; S_IN, DATA and S_OUT (the last slice of
// the Keccak-f witness) are private. A SHAKE256 call leaves bytes 136-167
// at zero (PUB = MASK = 0). Sponge builds the copies of a call: the first
// block has CONT = 0, a later block or a squeeze has CONT = 1 and links
// S_IN to the S_OUT of the previous copy. The constant bytes of a message
// (domain bytes, padding) are in PUB; its private bytes are in DATA, linked
// to the private inputs that define them.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_SPONGE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_SPONGE_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "arrays/packed_layer.h"
#include "circuits/compiler/compiler.h"
#include "circuits/tests/pq/credential/statement.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "circuits/tests/sha3/sha3_slicing.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "util/panic.h"

namespace proofs {
namespace pq_cred {

constexpr size_t kShake128Rate = 168;
constexpr size_t kShake256Rate = 136;
constexpr size_t kMaxRate = kShake128Rate;

// Input layout of one copy. Public: the constant one, CONT, PUB (8 * 168
// bits), MASK (8 * 168 bits). Private, from the first private input: S_IN
// (lane (x, y) at 64 (5 x + y)), DATA (byte i bit b at 8 i + b), S_OUT (as
// S_IN).
struct SpongeLayout {
  static constexpr size_t npub = 2 + 2 * 8 * kMaxRate;
  static constexpr size_t s_in = 0;
  static constexpr size_t data = 1600;
  static constexpr size_t s_out = data + 8 * kMaxRate;
  static constexpr size_t npriv = s_out + 1600;

  // Offset of bit B of rate byte I in a state (S_IN or S_OUT).
  static constexpr size_t state_bit(size_t i, size_t b) {
    return ((i / 8) % 5 * 5 + (i / 8) / 5) * 64 + 8 * (i % 8) + b;
  }
};

template <class LogicCircuit>
class SpongeStep {
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using v64 = typename LogicCircuit::v64;

 public:
  explicit SpongeStep(const LogicCircuit& lc) : lc_(lc) {}

  struct Public {
    BitW cont;
    std::array<v8, kMaxRate> pub, mask;
    void input(const LogicCircuit& lc) {
      cont = lc.input();
      for (auto& x : pub) x = lc.template vinput<8>();
      for (auto& x : mask) x = lc.template vinput<8>();
    }
  };

  struct Private {
    std::array<v64, 25> s_in;
    std::array<v8, kMaxRate> data;
    typename Sha3Circuit<LogicCircuit>::BlockWitness bw;
    void input(const LogicCircuit& lc) {
      for (auto& x : s_in) x = lc.template vinput<64>();
      for (auto& x : data) x = lc.template vinput<8>();
      bw.input(lc);
    }
  };

  void assert_step(const Public& u, const Private& w) const {
    v64 A[5][5];
    for (size_t x = 0; x < 5; ++x) {
      for (size_t y = 0; y < 5; ++y) A[x][y] = lc_.vand(u.cont, w.s_in[5 * x + y]);
    }
    for (size_t i = 0; i < kMaxRate; ++i) {
      const v8 in = lc_.vxor(u.pub[i], lc_.vand(u.mask[i], w.data[i]));
      const size_t lane = i / 8;
      for (size_t b = 0; b < 8; ++b) {
        auto& bit = A[lane % 5][lane / 5][8 * (i % 8) + b];
        bit = lc_.lxor(bit, in[b]);
      }
    }
    Sha3Circuit<LogicCircuit>(lc_).keccak_f_1600(A, w.bw);
  }

 private:
  const LogicCircuit& lc_;
};

// The copies of the sponge part (part PART of the statement) and their
// native values.
template <class Field>
class Sponge {
  using L = SpongeLayout;

 public:
  struct Copy {
    bool cont;
    uint8_t pub[kMaxRate], mask[kMaxRate], data[kMaxRate];
    uint64_t s_in[25], s_out[25];  // lane (x, y) at 5 x + y
  };

  Sponge(uint32_t part, Links<Field>& links) : part_(part), links_(links) {
    static_assert(L::npriv == 4544, "sponge layout");
    size_t slices = 0;
    for (size_t round = 0; round < 24; ++round) slices += sha3_slice_at(round);
    check(slices == 1, "the sponge step expects one SHA3 slice");
  }

  const std::vector<Copy>& copies() const { return copies_; }

  // SHAKE with rate RATE (136 or 168) of MSG; returns OUT_BYTES bytes of
  // output. If IN is not null, it receives MSG with every free bit
  // replaced by a reference to the private input that now defines it.
  Bytes shake(size_t rate, const Bytes& msg, size_t out_bytes,
              Bytes* in = nullptr) {
    check(rate == kShake128Rate || rate == kShake256Rate, "SHAKE rate");
    check(msg.size() % 8 == 0, "whole bytes");
    const size_t len = msg.size() / 8;
    const size_t nblocks = len / rate + 1;
    if (in != nullptr) *in = msg;
    for (size_t blk = 0; blk < nblocks; ++blk) {
      const size_t c = start(blk > 0);
      for (size_t i = 0; i < rate; ++i) {
        const size_t pos = blk * rate + i;
        for (size_t b = 0; b < 8; ++b) {
          Bit bit;
          if (pos < len) {
            bit = msg[8 * pos + b];
          } else {
            // pad10*1 with the SHAKE domain bits.
            const uint8_t pad =
                (pos == len ? 0x1F : 0) | (i == rate - 1 ? 0x80 : 0);
            bit = Bit::konst((pad >> b) & 1);
          }
          Copy& cp = copies_[c];
          if (bit.kind == Bit::kConst) {
            cp.pub[i] |= uint8_t(bit.value) << b;
          } else {
            const Ref r = ref(c, L::data + 8 * i + b);
            cp.mask[i] |= uint8_t(1) << b;
            cp.data[i] |= uint8_t(bit.value) << b;
            links_.bit(r, bit);
            if (in != nullptr && bit.kind == Bit::kFree) {
              (*in)[8 * pos + b] = Bit::ref(bit.value, r);
            }
          }
        }
      }
      permute(c);
    }

    Bytes out;
    out.reserve(8 * out_bytes);
    for (size_t o = 0; o < out_bytes; o += rate) {
      if (o > 0) permute(start(true));  // squeeze
      const size_t c = copies_.size() - 1;
      for (size_t i = 0; i < rate && o + i < out_bytes; ++i) {
        for (size_t b = 0; b < 8; ++b) {
          const size_t off = L::state_bit(i, b);
          out.push_back(Bit::ref(state_bit(copies_[c].s_out, off),
                                 ref(c, L::s_out + off)));
        }
      }
    }
    return out;
  }

  // The inputs of copy C as copy C of W (public and, unless PUBLIC_ONLY,
  // private), in the prover layout.
  void fill(PackedLayer<Field>& w, size_t c, bool public_only) const {
    const Copy& cp = copies_[c];
    size_t i = 0;
    w.set_bit(i++, c, true);
    w.set_bit(i++, c, cp.cont);
    for (uint8_t x : cp.pub) set_bits(w, i, c, x, 8);
    for (uint8_t x : cp.mask) set_bits(w, i, c, x, 8);
    check(i == L::npub, "sponge public inputs");
    if (public_only) return;
    for (uint64_t x : cp.s_in) set_bits(w, i, c, x, 64);
    for (uint8_t x : cp.data) set_bits(w, i, c, x, 8);
    for (uint64_t x : cp.s_out) set_bits(w, i, c, x, 64);
    check(i == L::npub + L::npriv, "sponge private inputs");
  }

  template <class LogicCircuit>
  static void inputs(const LogicCircuit& lc, QuadCircuit<Field>& Q,
                     typename SpongeStep<LogicCircuit>::Public& u,
                     typename SpongeStep<LogicCircuit>::Private& w) {
    u.input(lc);
    Q.private_input();
    w.input(lc);
  }

 private:
  Ref ref(size_t c, size_t off) const {
    return Ref{part_, static_cast<uint32_t>(c), static_cast<uint32_t>(off)};
  }

  static bool state_bit(const uint64_t s[25], size_t off) {
    return (s[off / 64] >> (off % 64)) & 1;
  }

  template <class X>
  static void set_bits(PackedLayer<Field>& w, size_t& i, size_t c, X x,
                       size_t nbits) {
    for (size_t b = 0; b < nbits; ++b) w.set_bit(i++, c, (x >> b) & 1);
  }

  // Appends a copy; with CONT, its S_IN is the S_OUT of the previous copy.
  size_t start(bool cont) {
    const size_t c = copies_.size();
    copies_.push_back(Copy{});
    Copy& cp = copies_.back();
    cp.cont = cont;
    if (cont) {
      std::memcpy(cp.s_in, copies_[c - 1].s_out, sizeof(cp.s_in));
      for (size_t k = 0; k < 1600; ++k) {
        links_.eq(ref(c, L::s_in + k), ref(c - 1, L::s_out + k));
      }
    }
    return c;
  }

  // The native permutation of copy C.
  void permute(size_t c) {
    Copy& cp = copies_[c];
    uint64_t A[5][5];
    for (size_t x = 0; x < 5; ++x) {
      for (size_t y = 0; y < 5; ++y) A[x][y] = cp.cont ? cp.s_in[5 * x + y] : 0;
    }
    for (size_t i = 0; i < kMaxRate; ++i) {
      const uint8_t in = cp.pub[i] ^ (cp.mask[i] & cp.data[i]);
      const size_t lane = i / 8;
      A[lane % 5][lane / 5] ^= uint64_t(in) << (8 * (i % 8));
    }
    Sha3Witness::BlockWitness bw;
    Sha3Witness::compute_witness_block(A, bw);
    for (size_t x = 0; x < 5; ++x) {
      for (size_t y = 0; y < 5; ++y) cp.s_out[5 * x + y] = bw.a_intermediate[23][x][y];
    }
  }

  const uint32_t part_;
  Links<Field>& links_;
  std::vector<Copy> copies_;
};

}  // namespace pq_cred
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_SPONGE_H_
