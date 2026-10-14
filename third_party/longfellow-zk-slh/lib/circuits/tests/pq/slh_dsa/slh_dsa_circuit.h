// The hash-step circuit of the SLH-DSA proof (not upstream): every copy
// proves one Keccak-f call of SLH-DSA verification (see slh_dsa.h).
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!  Experimental research code.
//
// For one copy, with the inputs of slh_dsa::Layout:
//
//   data   = BLOCK, with the two n-byte windows exchanged if SWAP_EN and SWAP
//   in     = PUB xor (MASK and data)
//   state  = in in the rate lanes, CONT ? CAP : 0 in the capacity lanes,
//            then Keccak-f, checked against the block witness; the output
//            is the last witness slice. For a later block of a call, the
//            links make BLOCK the previous output XOR the data.
//   active = not IS_WOTS, or J >= DIGIT
//   R      = active ? output[0, n) : BLOCK[window, window + n)
//   if IS_ACC: ACC_OUT = ACC_IN + (15 - DIGIT)
//
// R is the result of F or H; a WOTS+ chain step with J < DIGIT passes its
// input through, so that a chain of 15 copies computes chain(sig, DIGIT,
// 15 - DIGIT). The ACC chain computes the WOTS+ checksum.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_CIRCUIT_H_

#include <array>
#include <cstddef>

#include "circuits/tests/pq/slh_dsa/slh_dsa.h"
#include "circuits/tests/sha3/sha3_circuit.h"

namespace proofs {
namespace slh_dsa {

template <class LogicCircuit, size_t kN>
class StepCircuit {
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using v64 = typename LogicCircuit::v64;
  using v4 = typename LogicCircuit::template bitvec<4>;
  using vacc = typename LogicCircuit::template bitvec<kAccBits>;
  using L = Layout<kN>;

 public:
  explicit StepCircuit(const LogicCircuit& lc) : lc_(lc) {}

  // Public inputs, after the constant one (input 0).
  struct Public {
    std::array<v8, kRate> pub, mask;
    BitW cont, swap_en, is_wots;
    v4 j;
    BitW is_acc;

    void input(const LogicCircuit& lc) {
      for (auto& x : pub) x = lc.template vinput<8>();
      for (auto& x : mask) x = lc.template vinput<8>();
      cont = lc.input();
      swap_en = lc.input();
      is_wots = lc.input();
      j = lc.template vinput<4>();
      is_acc = lc.input();
    }
  };

  // Private inputs, in the order of Layout.
  struct Private {
    std::array<v64, kCapLanes> cap;
    std::array<v8, kRate> block;
    BitW swap;
    v4 digit;
    vacc acc_in, acc_out;
    std::array<v8, kN> r;
    typename Sha3Circuit<LogicCircuit>::BlockWitness bw;

    void input(const LogicCircuit& lc) {
      for (auto& x : cap) x = lc.template vinput<64>();
      for (auto& x : block) x = lc.template vinput<8>();
      swap = lc.input();
      digit = lc.template vinput<4>();
      acc_in = lc.template vinput<kAccBits>();
      acc_out = lc.template vinput<kAccBits>();
      for (auto& x : r) x = lc.template vinput<8>();
      bw.input(lc);
    }
  };

  void assert_step(const Public& u, const Private& w) const {
    const auto& [pub, mask, cont, swap_en, is_wots, j, is_acc] = u;
    const auto& block = w.block;
    const auto& digit = w.digit;
    const auto& r = w.r;

    // Absorb.
    const BitW sw = lc_.land(swap_en, w.swap);
    v64 A[5][5];
    for (size_t x = 0; x < 5; ++x) {
      for (size_t y = 0; y < 5; ++y) {
        const size_t lane = x + 5 * y;
        A[x][y] = lane < kRateLanes ? lc_.template vbit<64>(0)
                                    : lc_.vand(cont, w.cap[lane - kRateLanes]);
      }
    }
    for (size_t i = 0; i < kRate; ++i) {
      v8 data(block[i]);
      if (i >= L::window && i < L::window + 2 * kN) {
        const size_t other = i < L::window + kN ? i + kN : i - kN;
        for (size_t b = 0; b < 8; ++b) {
          data[b] = lc_.mux(sw, block[other][b], block[i][b]);
        }
      }
      const v8 in = lc_.vxor(pub[i], lc_.vand(mask[i], data));
      const size_t lane = i / 8;
      for (size_t b = 0; b < 8; ++b) {
        auto& bit = A[lane % 5][lane / 5][8 * (i % 8) + b];
        bit = lc_.lxor(bit, in[b]);
      }
    }

    Sha3Circuit<LogicCircuit> sha3(lc_);
    sha3.keccak_f_1600(A, w.bw);

    // Result.
    const BitW active = lc_.lor(lc_.lnot(is_wots), lc_.vleq(digit, j));
    for (size_t i = 0; i < kN; ++i) {
      const size_t lane = i / 8;
      for (size_t b = 0; b < 8; ++b) {
        const BitW out = A[lane % 5][lane / 5][8 * (i % 8) + b];
        lc_.assert_eq(r[i][b], lc_.mux(active, out, block[L::window + i][b]));
      }
    }

    // Checksum accumulator: 15 - DIGIT is the complement of DIGIT.
    vacc step;
    for (size_t b = 0; b < kAccBits; ++b) {
      step[b] = b < 4 ? lc_.lnot(digit[b]) : lc_.bit(0);
    }
    const vacc sum = lc_.vadd(w.acc_in, step);
    for (size_t b = 0; b < kAccBits; ++b) {
      lc_.assert0(lc_.land(is_acc, lc_.lxor(w.acc_out[b], sum[b])));
    }
  }

 private:
  const LogicCircuit& lc_;
};

}  // namespace slh_dsa
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_CIRCUIT_H_
