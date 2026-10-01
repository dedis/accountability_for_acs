// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_CIRCUIT_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/sha3/sha3_circuit.h"
#include "util/panic.h"

namespace proofs {

/**
 * @brief Zero-Knowledge circuit implementation for ML-DSA signature
 * verification.
 *
 * This class defines the constraints and witness validation logic required to
 * verify an ML-DSA (FIPS 204) signature within a Zero-Knowledge proof system.
 *
 * The verification process ensures that a prover can only produce a valid
 * proof if they possess a valid signature (z, h, c_tilde) for a given message
 * (bound via mu) and public key (A, t1).
 *
 * @tparam LogicCircuit
 * @tparam Field Fp24_6
 * @tparam Params The ML-DSA parameter set struct. This defines
 * signature-specific constants such as:
 *         - K, L: Matrix dimensions.
 *         - GAMMA_1, GAMMA_2: Coefficient range bounds.
 *         - BETA: Rejection bound.
 *         - OMEGA: Maximum number of ones in the hint.
 *         - TAU: Number of +/-1 in the challenge.
 *
 * Class Structure and Key Components:
 * - Public Inputs: Public Key (A_hat, nttt1, tr), Signature (c_tilde, z, h),
 * and Message Hash (mu).
 * - Witness: Internal helper variables supplied by the prover.
 * - Core Verification Pipeline (assert_valid_signature_on_mu):
 *   1. SampleInBall: Reconstructs the challenge polynomial 'c' from 'c_tilde'
 * using a constrained Fisher-Yates shuffle over SHAKE256 output.
 *   2. Matrix-Vector Multiplication: Computes w'_approx = A*z - c*t1*2^d in the
 * NTT domain.
 *   3. UseHint: Reconstructs the hinted high-bits w'_1 from w'_approx and hint
 * 'h'. This uses an optimized "Interval Shifting" technique with strict sign
 * constraints.
 *   4. Range Checks: Enforces strict infinity norm bounds on 'z' (||z||_infty <
 * gamma_1 - beta).
 *   5. Hash Commitment: Encodes w'_1 and asserts that SHAKE256(mu ||
 * encoded_w'_1) == c_tilde.
 */
template <class LogicCircuit, class Field, typename Params>
class MLDSAVerify {
  static constexpr size_t bit_width(size_t x) {
    return x == 0 ? 0 : 1 + bit_width(x >> 1);
  }

  using v_r1 = typename LogicCircuit::template bitvec<Params::r1_bits>;
  using v_h_sum =
      typename LogicCircuit::template bitvec<bit_width(Params::omega)>;
  using v8 = typename LogicCircuit::v8;
  using v16 = typename LogicCircuit::template bitvec<16>;
  using v_r0 = typename LogicCircuit::template bitvec<Params::r0_bits + 1>;
  using v_z = typename LogicCircuit::template bitvec<Params::z_bits>;
  using v64 = typename LogicCircuit::v64;
  using EltW = typename LogicCircuit::EltW;
  using Elt = typename Field::Elt;
  using BitW = typename LogicCircuit::BitW;
  using BlockWitness = typename Sha3Circuit<LogicCircuit>::BlockWitness;

 public:
  static constexpr size_t kOmegaBits = bit_width(Params::omega);

  struct RqW {
    std::array<EltW, ml_dsa::N> coeffs;

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < ml_dsa::N; ++i) {
        coeffs[i] = lc.eltw_input();
      }
    }
  };

  struct MatrixAW {
    std::array<std::array<RqW, Params::L>, Params::K> mat;

    void input(const LogicCircuit& lc) {
      for (size_t r = 0; r < Params::K; ++r) {
        for (size_t c = 0; c < Params::L; ++c) {
          mat[r][c].input(lc);
        }
      }
    }
  };

  struct Pk {
    MatrixAW a_hat;
    std::array<RqW, Params::K> nttt1;
    std::array<v8, 64> tr;

    void input(const LogicCircuit& lc) {
      a_hat.input(lc);
      for (size_t i = 0; i < Params::K; ++i) {
        nttt1[i].input(lc);
      }
      for (size_t i = 0; i < 64; ++i) {
        tr[i] = lc.template vinput<8>();
      }
    }
  };

  struct SignatureW {
    std::array<v8, Params::c_tilde_bytes> c_tilde;
    std::array<RqW, Params::L> z;
    std::array<std::array<v_z, ml_dsa::N>, Params::L> z_bits;
    std::array<RqW, Params::K> h;

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < Params::c_tilde_bytes; ++i) {
        c_tilde[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < Params::L; ++i) {
        z[i].input(lc);
      }
      for (size_t i = 0; i < Params::L; ++i) {
        for (size_t j = 0; j < ml_dsa::N; ++j) {
          z_bits[i][j] = lc.template vinput<Params::z_bits>();
        }
      }
      for (size_t i = 0; i < Params::K; ++i) {
        h[i].input(lc);
      }
    }
  };

  struct SampleInBallWitness {
    BlockWitness shake_bws;
    std::array<v8, Params::tau> j_vals;
    std::array<v16, Params::tau> j_k_indices;
    std::vector<std::vector<v8>> position_trace;

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < Params::tau; ++i) {
        j_vals[i] = lc.template vinput<8>();
        j_k_indices[i] = lc.template vinput<16>();
      }
      shake_bws.input(lc);
      if (position_trace.empty()) {
        position_trace.resize(Params::tau);
      }
      for (size_t s = 0; s < Params::tau; ++s) {
        if (position_trace[s].size() != s + 1) {
          position_trace[s].resize(s + 1);
        }
        for (size_t k = 0; k <= s; ++k) {
          position_trace[s][k] = lc.template vinput<8>();
        }
      }
    }
  };

  class Witness {
   public:
    SampleInBallWitness sample_in_ball_;
    RqW c_;
    RqW w_prime_approx_[Params::K];
    RqW w1_[Params::K];
    std::array<std::array<v_r1, ml_dsa::N>, Params::K> w1_bits_;
    std::array<std::array<v_r0, ml_dsa::N>, Params::K> hint_aux_bits_;
    RqW w_prime_1_[Params::K];
    std::array<std::array<v_r1, ml_dsa::N>, Params::K> w_prime_1_bits_;
    std::array<RqW, Params::L> nttz_;
    RqW nttc_;
    std::array<v8, Params::K * Params::w1_bytes> w1_tilde_;
    std::vector<BlockWitness> c_prime_tilde_bws_;
    v_h_sum h_sum_bits_;

    void input(const LogicCircuit& lc) {
      sample_in_ball_.input(lc);
      c_.input(lc);
      for (size_t i = 0; i < Params::K; ++i) {
        w_prime_approx_[i].input(lc);
        w1_[i].input(lc);
        for (size_t j = 0; j < ml_dsa::N; ++j) {
          w1_bits_[i][j] = lc.template vinput<Params::r1_bits>();
        }
        for (size_t j = 0; j < ml_dsa::N; ++j) {
          hint_aux_bits_[i][j] = lc.template vinput<Params::r0_bits + 1>();
        }
        w_prime_1_[i].input(lc);
        for (size_t j = 0; j < ml_dsa::N; ++j) {
          w_prime_1_bits_[i][j] = lc.template vinput<Params::r1_bits>();
        }
      }
      for (size_t i = 0; i < Params::L; ++i) {
        nttz_[i].input(lc);
      }
      nttc_.input(lc);
      for (auto& w1 : w1_tilde_) {
        w1 = lc.template vinput<8>();
      }
      for (auto& bw : c_prime_tilde_bws_) {
        bw.input(lc);
      }
      h_sum_bits_ = lc.template vinput<kOmegaBits>();
    }
  };

  void matrix_vector_mul(const MatrixAW& A, const std::array<RqW, Params::L>& x,
                         std::array<RqW, Params::K>& y) const {
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t c = 0; c < ml_dsa::N; ++c) {
        y[i].coeffs[c] = lc_.konst(lc_.f_.zero());
      }
      for (size_t j = 0; j < Params::L; ++j) {
        for (size_t c = 0; c < ml_dsa::N; ++c) {
          y[i].coeffs[c] = lc_.add(
              y[i].coeffs[c], lc_.mul(A.mat[i][j].coeffs[c], x[j].coeffs[c]));
        }
      }
    }
  }

  void scalar_vector_mul(const RqW& c, const std::array<RqW, Params::K>& x,
                         std::array<RqW, Params::K>& y) const {
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        y[i].coeffs[k] = lc_.mul(c.coeffs[k], x[i].coeffs[k]);
      }
    }
  }

  void assert_ntt(const RqW& c, const RqW& cprime) const {
    std::vector<EltW> p(c.coeffs.begin(), c.coeffs.end());
    int k = 1;
    int length = ml_dsa::N / 2;
    while (length > 0) {
      for (int start = 0; start < ml_dsa::N; start += 2 * length) {
        auto zeta = lc_.f_.of_scalar_field(ml_dsa::kZetas[k]);
        auto neg_zeta = lc_.f_.negf(zeta);
        k++;
        for (int j = start; j < start + length; ++j) {
          auto t = lc_.axpy(p[j], zeta, p[j + length]);
          p[j + length] = lc_.axpy(p[j], neg_zeta, p[j + length]);
          p[j] = t;
        }
      }
      length /= 2;
    }
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      lc_.assert_eq(p[i], cprime.coeffs[i]);
    }
  }

  void assert_inverse_ntt(const RqW& c, const RqW& cprime) const {
    std::vector<EltW> p(c.coeffs.begin(), c.coeffs.end());
    int k = 256;
    int length = 1;
    while (length < ml_dsa::N) {
      for (int start = 0; start < ml_dsa::N; start += 2 * length) {
        k--;
        auto neg_zeta = lc_.f_.negf(lc_.f_.of_scalar_field(ml_dsa::kZetas[k]));
        for (int j = start; j < start + length; ++j) {
          auto t = p[j];
          p[j] = lc_.add(t, p[j + length]);
          auto diff = lc_.sub(t, p[j + length]);
          p[j + length] = lc_.mul(neg_zeta, diff);
        }
      }
      length *= 2;
    }

    auto f = lc_.konst(lc_.f_.of_scalar_field(8347681u));
    for (size_t i = 0; i < ml_dsa::N; ++i) {
      p[i] = lc_.mul(f, p[i]);
      lc_.assert_eq(p[i], cprime.coeffs[i]);
    }
  }

  explicit MLDSAVerify(const LogicCircuit& lc) : lc_(lc) {}

  // Validates the "UseHint" operation for a single coefficient, ensuring that
  // the high bits `w_prime_1` are correctly derived from the approximate high
  // bits `w_prime_approx` and the hint `h` according to FIPS 204.
  //
  // FIPS UseHint(h, r) Standard Logic:
  // 1. Decompose `r = r1 * 2*gamma2 + r0` where `-gamma2 < r0 <= gamma2`.
  // 2. If `h == 1` and `r0 > 0`, return `(r1 + 1) mod 44`.
  // 3. If `h == 1` and `r0 <= 0`, return `(r1 - 1) mod 44`.
  // 4. If `h == 0`, return `r1`.
  //
  // Our Circuit Optimization:
  // This function uses an optimized algorithm (interval shifting) that offloads
  // the computation of the expected answer `hinted_r1` to the prover and
  // requires ONLY ONE range check.
  //
  // Specifically, this function asserts:
  // 1. Shift Indicator `c` derivation:
  //    - Extracts the 19th bit of `hint_r0_bits_elt` as a sign bit `s`.
  //    - Compute `c = h * (1 - 2*s)`. This maps `h=0 -> c=0`, and `h=1 -> c
  //    \in {-1, 1}`.
  //    - This carefully aligns with the FIPS standard constraints: if the hint
  //    `h` is 1, `c` will tell us whether we are shifting `r1` by +1
  //    (`c=1`, because `r0 > 0`) or by -1 (`c=-1`, because `r0 <= 0`).
  //    If `h = 0`, no shift applies (`c=0`).
  //
  // 2. Decomposition and Range check for `r0`:
  //    - The approximated value `r` decomposes into `r1` and `r0` such that:
  //      `r0 = r - r1 * 2*gamma2`
  //    - If we follow the standard, `r0` must lie in `(-gamma2, gamma2]`.
  //    - Instead of range-checking `r0` over this signed interval, we assert
  //      that `r0_shifted = r0 - c * 2*gamma2 + (gamma2 - 1)` must lie
  //      strictly in `[0, 2*gamma2 - 1]`.
  //    - By adding `(gamma2 - 1)`, we functionally shift the legitimate range
  //    to be strictly non-negative.
  //    - By subtracting `c * 2*gamma2`, we logically enforce the explicit FIPS
  //    boundaries on `r0` depending on `c`:
  //      - If `c = 1` (`r1` shifts +1), then `r0` MUST have been `> 0`.
  //      - If `c = -1` (`r1` shifts -1), then `r0` MUST have been `<= 0`.
  //    - This requires only one range check by reconstructing `r0_shifted` from
  //    the first 18 bits of `hint_r0_bits_elt` and bounds checking `r0_shifted
  //    <= 2*gamma2 - 1`.
  //
  // 3. Modulo check on computed `hinted_r1`:
  //    - Verifies that `hinted_r1` is indeed congruent to the raw (unmoduloed)
  //    shift `r1 + c` meaning `(r1 + c - hinted_r1) \in {0, 44, -44}`.
  //
  // 4. Range check on `hinted_r1` bounds:
  //    - `hinted_r1` is the final answer supplied by the prover.
  //    - It is explicitly reconstructed from boolean bits `r1_bits_elt`
  //    matching bounded `[0, 43]`.
  void assert_use_hint_single(const EltW& h_elt, const EltW& r_elt,
                              const EltW& r1_raw, const v_r1& r1_raw_bits_elt,
                              const v_r0& hint_r0_bits_elt,
                              const EltW& hinted_r1,
                              const v_r1& r1_bits_elt) const {
    auto two_gamma2 = lc_.konst(lc_.f_.of_scalar(2 * Params::gamma_2));
    auto shift_val = lc_.konst(lc_.f_.of_scalar(Params::gamma_2));
    EltW zero = lc_.konst(lc_.f_.zero());

    lc_.assert_is_bit(h_elt);

    EltW r1_raw_recon = lc_.as_scalar(r1_raw_bits_elt);
    lc_.assert_eq(r1_raw, r1_raw_recon);
    auto r1_bound = lc_.template vbit<Params::r1_bits>(Params::M - 1);
    auto is_w1_raw_valid =
        lc_.leq(Params::r1_bits, r1_raw_bits_elt.data(), r1_bound.data());
    lc_.assert1(is_w1_raw_valid);

    EltW r0_shifted =
        lc_.as_scalar(lc_.template slice<0, Params::r0_bits>(hint_r0_bits_elt));

    auto max_bound = lc_.template vbit<Params::r0_bits>(2 * Params::gamma_2);
    auto is_leq_max =
        lc_.leq(Params::r0_bits, hint_r0_bits_elt.data(), max_bound.data());
    lc_.assert1(is_leq_max);

    BitW s_bit = hint_r0_bits_elt[Params::r0_bits];

    // Constrain s_bit to be equal to (r0_shifted <= gamma_2) to prevent prover
    // from cheating.
    auto r0_shifted_vec =
        lc_.template slice<0, Params::r0_bits>(hint_r0_bits_elt);
    BitW is_leq = lc_.vleq(r0_shifted_vec, Params::gamma_2);
    lc_.assert_eq(lc_.eval(s_bit), lc_.eval(is_leq));

    EltW neg_h = lc_.sub(zero, h_elt);
    EltW c_elt = lc_.mux(s_bit, neg_h, h_elt);

    // delta = R - (gamma2 - 1)
    EltW delta = lc_.sub(r0_shifted, shift_val);

    EltW term1 = lc_.mul(r1_raw, two_gamma2);
    EltW val = lc_.add(term1, delta);
    lc_.assert_eq(r_elt, val);

    EltW r1_recon = lc_.as_scalar(r1_bits_elt);
    lc_.assert_eq(hinted_r1, r1_recon);
    auto is_w1_valid =
        lc_.leq(Params::r1_bits, r1_bits_elt.data(), r1_bound.data());
    lc_.assert1(is_w1_valid);

    EltW diff = lc_.sub(r1_raw, hinted_r1);
    EltW true_shift_diff = lc_.add(diff, c_elt);

    EltW m = lc_.konst(lc_.f_.of_scalar(Params::M));
    EltW diff_minus_M = lc_.sub(true_shift_diff, m);
    EltW diff_plus_M = lc_.add(true_shift_diff, m);

    EltW prod1 = lc_.mul(true_shift_diff, diff_minus_M);
    EltW prod2 = lc_.mul(prod1, diff_plus_M);
    lc_.assert0(prod2);
  }

  void assert_use_hint(
      const std::array<RqW, Params::K>& h,
      const RqW (&w_prime_approx)[Params::K], const RqW (&w1)[Params::K],
      const std::array<std::array<v_r1, ml_dsa::N>, Params::K>& w1_bits,
      const std::array<std::array<v_r0, ml_dsa::N>, Params::K>& hint_aux_bits,
      const RqW (&w_prime_1)[Params::K],
      const std::array<std::array<v_r1, ml_dsa::N>, Params::K>& w_prime_1_bits,
      const v_h_sum& h_sum_bits) const {
    EltW sum = lc_.konst(lc_.f_.zero());
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        assert_use_hint_single(h[i].coeffs[k], w_prime_approx[i].coeffs[k],
                               w1[i].coeffs[k], w1_bits[i][k],
                               hint_aux_bits[i][k], w_prime_1[i].coeffs[k],
                               w_prime_1_bits[i][k]);
        sum = lc_.add(sum, h[i].coeffs[k]);
      }
    }

    auto is_valid_weight = lc_.vleq(h_sum_bits, Params::omega);
    lc_.assert1(is_valid_weight);

    EltW reconstructed_sum = lc_.as_scalar(h_sum_bits);
    lc_.assert_eq(sum, reconstructed_sum);
  }

  // Verifies that the infinity norm of the polynomial vector `vec` is within
  // the specified `bound`. This function checks that each coefficient `c` of
  // `vec` satisfies `-bound <= c < bound` (i.e., `c \in [-bound, bound - 1]`).
  //
  // The verification is performed using a provided bit-decomposition `vec_bits`
  // for each coefficient. The steps are:
  // 1. Reconstruct a value `r` from `vec_bits` such that `r = sum(bits * 2^k)`.
  //    This `r` represents the shifted coefficient `c + bound`.
  // 2. Assert that `vec[i][j] + bound == r`. This ensures that the
  //    bit-decomposition `vec_bits` corresponds to the coefficient `vec[i][j]`
  //    shifted by `bound`.
  // 3. Assert that `r <= 2 * bound - 1`. Since `r` is non-negative (from bits),
  //    this enforces `0 <= c + bound <= 2 * bound - 1`, which simplifies to
  //    `-bound <= c <= bound - 1`.
  template <size_t SIZE, size_t BIT_WIDTH>
  void assert_infty_norm(
      const std::array<RqW, SIZE>& vec,
      const std::array<
          std::array<typename LogicCircuit::template bitvec<BIT_WIDTH>,
                     ml_dsa::N>,
          SIZE>& vec_bits,
      uint64_t bound) const {
    for (size_t i = 0; i < SIZE; ++i) {
      for (size_t j = 0; j < ml_dsa::N; ++j) {
        EltW r = lc_.as_scalar(vec_bits[i][j]);

        // Shift by bound - 1 to enforce strictly greater than -bound.
        EltW shifted_original =
            lc_.add(vec[i].coeffs[j], lc_.konst(lc_.f_.of_scalar(bound - 1)));
        lc_.assert_eq(shifted_original, r);

        // Bound by 2 * bound - 2 to enforce strictly less than bound.
        auto is_leq =
            lc_.leq(BIT_WIDTH, vec_bits[i][j].data(),
                    lc_.template vbit<BIT_WIDTH>(2 * bound - 2).data());
        lc_.assert1(is_leq);
      }
    }
  }

  // Verifies the `w1Encode` operation, which serializes the polynomial vector
  // `w_prime_1` into a byte array. This byte array is subsequently used to
  // hash (along with `mu`) and validate the signature challenge `c_tilde`.
  //
  // The encoding constraints are structured and validated as follows:
  // 1. **Bit Extraction**:
  //    - Each coefficient in `w_prime_1` is bounded in `[0, 43]` and is
  //      fully represented using exactly 6 bits.
  //    - The method iterates through all `K` polynomials and all `N` (256)
  //      coefficients, extracting the lowest 6 bits of each coefficient.
  //    - These bits are concatenated into a flat array of `K * N * 6` bits.
  // 2. **Byte Packing (SimpleBitPack)**:
  //    - The bit array is partitioned into 8-bit subsets to form bytes.
  //    - As required by FIPS 204 Algorithm 18 (`SimpleBitPack`), bits are
  //      packed in little-endian order, meaning the first bit of each subset
  //      is bound to the Least Significant Bit (LSB) of the output byte.
  // 3. **Padding Constraints**:
  //    - The algorithm enforces that if the total bit count is not perfectly
  //      divisible by 8, any residual bits making up the final byte are
  //      constrained to zero-wires (`lc_.bit(0)`).
  void assert_w1_encode(
      const std::array<std::array<v_r1, ml_dsa::N>, Params::K>& w_prime_1_bits,
      const std::array<v8, Params::K * Params::w1_bytes>& putative_w1_tilde)
      const {
    size_t bitlen = Params::r1_bits;
    size_t total_bytes = Params::K * Params::w1_bytes;

    std::vector<BitW> all_bits;
    all_bits.reserve(Params::K * ml_dsa::N * bitlen);

    for (size_t k = 0; k < Params::K; ++k) {
      for (size_t i = 0; i < ml_dsa::N; ++i) {
        for (size_t b = 0; b < bitlen; ++b) {
          all_bits.push_back(w_prime_1_bits[k][i][b]);
        }
      }
    }

    for (size_t i = 0; i < total_bytes; ++i) {
      v8 byte_val;
      for (size_t b = 0; b < 8; ++b) {
        if (i * 8 + b < all_bits.size()) {
          byte_val[b] = all_bits[i * 8 + b];
        } else {
          byte_val[b] = lc_.bit(0);
        }
      }
      lc_.vassert_eq(putative_w1_tilde[i], byte_val);
    }
  }

  // Verifies the "SampleInBall" operation, which generates a sparse polynomial
  // `c` with coefficients in {-1, 0, 1} and exactly `TAU` non-zero
  // coefficients. This corresponds to Algorithm 29 in FIPS 204.
  //
  // 4: (ctx, s) <- H.Squeeze(ctx, 8)
  // 5: h <- BytesToBits(s)    # 64 bits for -1,1
  // 6: for i from 256 - TAU to 255 do
  // 7:   (ctx, j) <- H.Squeeze(ctx, 1)
  // 8:   while j > i do       #  rejection sampling in {0, … , i}
  // 9:     (ctx, j) <- H.Squeeze(ctx, 1)
  // 10:  end while            # j is a pseudorandom byte that is ≤ i
  // 11:  c_i <- c_j
  // 12:  c_j <- (-1)^h[i + TAU - 256]
  // 13: end for
  //
  // The function validates the generation of `c` from the seed `rho`:
  // 1. **SHAKE256**: Computes 272b of SHAKE256 output `out` from `rho`.
  // 2. **Rejection Sampling Verification**: The algorithm picks `TAU` indices
  //    `j` using rejection sampling from `out` (starting at byte 8). For each
  //    step `s` (target index `i = 256 - TAU + s`):
  //    - The witness provides the index `k_idx` in `out` where a valid sample
  //    `j` was found.
  //    - **Validation**:
  //      - `out[k_idx] == j`: verifies the witness `j` matches the SHAKE
  //      output.
  //      - `j <= i`: verifies the sample is within the valid range for the
  //      swap.
  //      - For all `k` such that `prev_k_index <= k < k_idx`: verifies `out[k]
  //      > i`.
  //        This ensures that all skipped bytes were legitimately rejected
  //        because they were out of range.
  //
  // 3. **Shuffle Trace Verification (Parallel)**:
  //    - Instead of sequentially updating the polynomial `c`, we verify a
  //      "trace" of the shuffle positions witnessed by
  //      `witness.position_trace`.
  //    - For each step `s`, we verify that `position_trace[s]` is correctly
  //      derived from `position_trace[s-1]` by swapping the element at `j` with
  //      `i`.
  //    - This allows all `s` steps to be verified in parallel, reducing the
  //      circuit depth from O(TAU) to O(1) (relative to the shuffle steps).
  //
  // 4. **Final Polynomial Construction**:
  //    - Constructs the expected polynomial `c` from the final positions in
  //      `position_trace[TAU-1]`.
  //    - For each coefficient index `k`, we sum the contributions from all `s`
  //      (where `final_pos[s] == k`).
  //    - `c[k] = sum_{s} (final_pos[s] == k ? (-1)^sign_s : 0)`.
  //    - Asserts that `cprime` matches this constructed `c`.
  void assert_sample_in_ball(const std::array<v8, Params::c_tilde_bytes>& rho,
                             const RqW& cprime,
                             const SampleInBallWitness& witness) const {
    Sha3Circuit<LogicCircuit> sha3(lc_);
    std::vector<v8> out;
    std::vector<v8> rho_vec(rho.begin(), rho.end());
    size_t out_bytes = 136;
    std::vector<BlockWitness> bws;
    bws.push_back(witness.shake_bws);
    sha3.assert_shake256(rho_vec, out_bytes, out, bws);

    v16 prev_k_index = lc_.template vbit<16>(8);

    for (size_t s = 0; s < Params::tau; ++s) {
      size_t i = 256 - Params::tau + s;
      const v8& j = witness.j_vals[s];
      const v16& k_idx = witness.j_k_indices[s];

      auto is_in_bounds = lc_.vleq(k_idx, out.size() - 1);
      lc_.assert1(is_in_bounds);

      auto is_increasing = lc_.vleq(prev_k_index, k_idx);
      lc_.assert1(is_increasing);

      v16 j_ext = lc_.template vbit<16>(0);
      for (size_t k = 0; k < 8; ++k) j_ext[k] = j[k];

      v16 i_vec = lc_.template vbit<16>(i);
      auto j_valid = lc_.vleq(j_ext, i_vec);
      lc_.assert1(j_valid);

      for (size_t k = 0; k < out.size(); ++k) {
        v16 curr_k = lc_.template vbit<16>(k);
        auto is_target = lc_.veq(curr_k, k_idx);

        auto match_val = lc_.veq(out[k], j);
        lc_.assert_implies(is_target, match_val);

        auto gt_prev = lc_.vleq(prev_k_index, curr_k);
        auto lt_target = lc_.vlt(curr_k, k_idx);
        auto in_range = lc_.land(gt_prev, lt_target);

        v16 out_k_ext = lc_.template vbit<16>(0);
        for (size_t b = 0; b < 8; ++b) out_k_ext[b] = out[k][b];

        auto rejected_val = lc_.vlt(i_vec, out_k_ext);
        lc_.assert_implies(in_range, rejected_val);
      }
      prev_k_index = lc_.vadd(k_idx, 1);
    }

    lc_.vassert_eq(witness.position_trace[0][0], witness.j_vals[0]);

    for (size_t s = 1; s < Params::tau; ++s) {
      size_t i = 256 - Params::tau + s;
      const v8& j = witness.j_vals[s];

      const auto& prev_pos = witness.position_trace[s - 1];
      const auto& curr_pos = witness.position_trace[s];

      lc_.vassert_eq(curr_pos[s], j);

      for (size_t k = 0; k < s; ++k) {
        const auto& p = prev_pos[k];
        auto is_j = lc_.veq(p, j);
        v8 i_v = lc_.template vbit<8>(i);
        v8 target;
        for (size_t b = 0; b < 8; ++b) {
          target[b] = lc_.mux(is_j, i_v[b], p[b]);
        }
        lc_.vassert_eq(curr_pos[k], target);
      }
    }

    const auto& final_pos = witness.position_trace[Params::tau - 1];
    EltW one = lc_.konst(lc_.f_.one());
    EltW mone = lc_.konst(lc_.f_.mone());
    EltW zero = lc_.konst(lc_.f_.zero());

    std::vector<EltW> trace_vals(Params::tau);
    for (size_t s = 0; s < Params::tau; ++s) {
      size_t bit_idx = s;
      size_t byte_idx = bit_idx / 8;
      size_t bit_shift = bit_idx % 8;
      auto sign_bit = out[byte_idx][bit_shift];
      trace_vals[s] = lc_.mux(sign_bit, mone, one);
    }

    for (size_t k = 0; k < ml_dsa::N; ++k) {
      v8 k_v = lc_.template vbit<8>(k);

      EltW val_k = lc_.add(0, Params::tau, [&](size_t s) {
        auto is_match = lc_.veq(final_pos[s], k_v);
        return lc_.mux(is_match, trace_vals[s], zero);
      });

      lc_.assert_eq(cprime.coeffs[k], val_k);
    }
  }

  std::vector<v8> prepare_mu_input(const std::array<v8, 64>& tr, const v8* msg,
                                   size_t len) const {
    std::vector<v8> input_bytes;
    input_bytes.reserve(64 + len + 2);
    for (size_t i = 0; i < 64; ++i) input_bytes.push_back(tr[i]);
    for (size_t i = 0; i < len; ++i) input_bytes.push_back(msg[i]);

    size_t rate = 136;
    size_t original_len = input_bytes.size();
    size_t padding_len = rate - (original_len % rate);

    if (padding_len == 1) {
      auto pad = lc_.template vbit<8>(0x9F);
      input_bytes.push_back(pad);
    } else {
      auto pad1 = lc_.template vbit<8>(0x1F);
      input_bytes.push_back(pad1);

      auto zero = lc_.template vbit<8>(0);
      for (size_t i = 0; i < padding_len - 2; ++i) {
        input_bytes.push_back(zero);
      }

      auto pad2 = lc_.template vbit<8>(0x80);
      input_bytes.push_back(pad2);
    }

    check(input_bytes.size() % rate == 0, "Padding failed");
    return input_bytes;
  }

  void assert_mu(const std::array<v8, 64>& tr, const v8* msg, size_t len,
                 const std::vector<BlockWitness>& mu_bws,
                 const std::array<v8, 64>& mu) const {
    Sha3Circuit<LogicCircuit> sha3(lc_);
    using v64 = typename LogicCircuit::template bitvec<64>;
    v64 A[5][5];
    for (int x = 0; x < 5; ++x) {
      for (int y = 0; y < 5; ++y) {
        A[x][y] = lc_.template vbit<64>(0);
      }
    }

    std::vector<v8> input_bytes = prepare_mu_input(tr, msg, len);
    size_t rate = 136;
    size_t num_blocks = input_bytes.size() / rate;

    size_t input_idx = 0;
    size_t bw_idx = 0;

    for (size_t b_idx = 0; b_idx < num_blocks; ++b_idx) {
      size_t x = 0, y = 0;
      for (size_t i = 0; i < rate; i += 8) {
        v64 a;
        for (size_t b = 0; b < 8; ++b) {
          for (size_t j = 0; j < 8; ++j) {
            if (i + b < rate) {
              a[b * 8 + j] = input_bytes[input_idx + i + b][j];
            }
          }
        }
        A[x][y] = lc_.vxor(A[x][y], a);
        ++x;
        if (x == 5) {
          ++y;
          x = 0;
        }
      }
      input_idx += rate;

      check(bw_idx < mu_bws.size(), "Not enough BlockWitnesses for mu");
      sha3.keccak_f_1600(A, mu_bws[bw_idx++]);
    }

    std::vector<v8> squeezed(64);
    size_t x = 0, y = 0;
    for (size_t i = 0; i < 64; i += 8) {
      for (size_t b = 0; b < 8; ++b) {
        for (size_t j = 0; j < 8; ++j) {
          squeezed[i + b][j] = A[x][y][b * 8 + j];
        }
      }
      ++x;
      if (x == 5) {
        ++y;
        x = 0;
      }
    }

    for (size_t i = 0; i < 64; ++i) {
      for (size_t b = 0; b < 8; ++b) {
        lc_.assert_eq(squeezed[i][b], mu[i][b]);
      }
    }
  }

  void assert_w_prime_approx(const Pk& pk, const SignatureW& sig,
                             const Witness& w) const {
    for (size_t i = 0; i < Params::L; ++i) {
      assert_ntt(sig.z[i], w.nttz_[i]);
    }
    assert_ntt(w.c_, w.nttc_);

    std::array<RqW, Params::K> Az;
    std::array<RqW, Params::K> ct1;
    matrix_vector_mul(pk.a_hat, w.nttz_, Az);
    scalar_vector_mul(w.nttc_, pk.nttt1, ct1);

    for (size_t i = 0; i < Params::K; ++i) {
      RqW diff;
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        diff.coeffs[k] = lc_.sub(Az[i].coeffs[k], ct1[i].coeffs[k]);
      }
      assert_inverse_ntt(diff, w.w_prime_approx_[i]);
    }
  }

  void assert_ctilde(
      const std::array<v8, 64>& mu,
      const std::array<v8, Params::K * Params::w1_bytes>& w_prime_1_bytes,
      const std::vector<BlockWitness>& c_prime_tilde_bws,
      const std::array<v8, Params::c_tilde_bytes>& c_tilde) const {
    Sha3Circuit<LogicCircuit> sha3(lc_);

    std::vector<v8> input_bytes;
    input_bytes.insert(input_bytes.end(), mu.begin(), mu.end());
    input_bytes.insert(input_bytes.end(), w_prime_1_bytes.begin(),
                       w_prime_1_bytes.end());

    std::vector<v8> squeezed(Params::c_tilde_bytes);

    sha3.assert_shake256(input_bytes, Params::c_tilde_bytes, squeezed,
                         c_prime_tilde_bws);

    for (size_t i = 0; i < Params::c_tilde_bytes; ++i) {
      lc_.vassert_eq(squeezed[i], c_tilde[i]);
    }
  }

  void assert_valid_signature_on_mu(const Pk& pk, const SignatureW& sig,
                                    const std::array<v8, 64>& mu,
                                    const Witness& w) const {
    // 7.  c = SampleInBall(c_tilde)
    // Generate the challenge c from the commitment c_tilde.
    // c: R_q with small coefficients (weights +/- 1).
    assert_sample_in_ball(sig.c_tilde, w.c_, w.sample_in_ball_);

    // 8. Compute w'_Approx in the NTT domain.
    // w_prime_approx = InverseNTT( A_hat o NTT(z) - NTT(c) o NTT(t1 * 2^d) )
    // w_prime_approx: Vector of K polynomials in R_q.
    assert_w_prime_approx(pk, sig, w);

    // 9.  w_prime_1 = UseHint(h, w_prime_approx)
    //     Use hint h to reconstruct the exact high bits w1 \in R_q^K.
    assert_use_hint(sig.h, w.w_prime_approx_, w.w1_, w.w1_bits_,
                    w.hint_aux_bits_, w.w_prime_1_, w.w_prime_1_bits_,
                    w.h_sum_bits_);

    // 10. Encode w_prime_1 into a byte array for hashing.
    // w1_tilde: Byte array containing the packed bits of w_prime_1.
    assert_w1_encode(w.w_prime_1_bits_, w.w1_tilde_);

    // 11. Verification Check 1: ||z|| < (gamma1 - beta)
    assert_infty_norm<Params::L, Params::z_bits>(
        sig.z, sig.z_bits, Params::gamma_1 - Params::beta);

    // 12. Verification Check 2: c_prime = H(mu || w1Encode(w_prime_1), 32)
    assert_ctilde(mu, w.w1_tilde_, w.c_prime_tilde_bws_, sig.c_tilde);
  }

 private:
  const LogicCircuit& lc_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_CIRCUIT_H_
