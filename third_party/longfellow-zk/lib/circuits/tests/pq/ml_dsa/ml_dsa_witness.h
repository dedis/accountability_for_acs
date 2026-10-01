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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_WITNESS_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "algebra/fp24.h"
#include "arrays/dense.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/sha3/sha3_witness.h"

namespace proofs {

template <typename Params>
class ml_dsa_witness {
 public:
  std::array<uint8_t, 64> tr_;
  std::array<uint8_t, Params::c_tilde_bytes> c_tilde_;
  std::array<uint8_t, 64> mu_;
  std::array<uint8_t, Params::K * Params::w1_bytes> w1_tilde_;

  std::array<uint8_t, Params::c_tilde_bytes> c_prime_tilde_;
  std::vector<Sha3Witness::BlockWitness> c_prime_tilde_bws_;
  std::array<std::array<uint64_t, ml_dsa::N>, Params::L> z_bits_;
  uint64_t h_sum_bits_;

  Sha3Witness::BlockWitness shake_bws_;

  std::array<uint8_t, Params::tau> j_vals_;
  std::array<uint16_t, Params::tau> j_k_indices_;
  std::array<std::array<uint8_t, Params::tau>, Params::tau> position_trace_{};
  ml_dsa::Rq c_coeffs_;  // Polynomial c in domain

  static int64_t SymmetricReduce(int64_t delta) {
    delta = delta % static_cast<int64_t>(ml_dsa::Q);
    if (delta > static_cast<int64_t>(ml_dsa::Q) / 2) {
      delta -= ml_dsa::Q;
    }
    return delta;
  }

  // Derived NTT values
  typename ml_dsa::MLDsaTypes<Params>::RqL nttz_;
  ml_dsa::Rq nttc_;  // Single poly
  typename ml_dsa::MLDsaTypes<Params>::RqK nttt1_;
  typename ml_dsa::MLDsaTypes<Params>::RqK w_prime_approx_;
  std::array<std::array<int32_t, ml_dsa::N>, Params::K> w1_;
  std::array<std::array<uint64_t, ml_dsa::N>, Params::K> hint_aux_bits_;
  std::array<std::array<int32_t, ml_dsa::N>, Params::K> w_prime_1_;
  std::array<std::array<uint64_t, ml_dsa::N>, Params::K> w_prime_1_bits_;
  std::array<std::array<uint64_t, ml_dsa::N>, Params::K> w1_bits_;

  // Public inputs or derived values
  std::array<uint8_t, 32> rho_;
  typename ml_dsa::MLDsaTypes<Params>::RqK t1_;

  const Fp24& f_ = ml_dsa::Fq();

  typename ml_dsa::MLDsaTypes<Params>::PublicKey ref_pk_;
  typename ml_dsa::MLDsaTypes<Params>::Signature ref_sig_;
  std::vector<uint8_t> msg_;

  template <typename Field>
  void fill_pk(DenseFiller<Field>& filler, const Field& f) const {
    // 1. Pk
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t j = 0; j < Params::L; ++j) {
        for (size_t k = 0; k < ml_dsa::N; ++k) {
          filler.push_back(f.of_scalar(ref_pk_.a_hat[i][j][k]));
        }
      }
    }
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        filler.push_back(f.of_scalar(nttt1_[i][k]));
      }
    }
    for (size_t i = 0; i < 64; ++i) {
      filler.push_back(tr_[i], 8, f);
    }
  }

  template <typename Field>
  void fill_witness(DenseFiller<Field>& filler, const Field& f) const {
    fill_pk(filler, f);

    // 2. Sig
    for (size_t i = 0; i < Params::c_tilde_bytes; ++i) {
      filler.push_back(c_tilde_[i], 8, f);
    }
    for (size_t i = 0; i < Params::L; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        filler.push_back(f.of_scalar(ref_sig_.z[i][k]));
      }
    }
    for (size_t i = 0; i < Params::L; ++i) {
      for (size_t j = 0; j < ml_dsa::N; ++j) {
        filler.push_back(z_bits_[i][j], Params::z_bits, f);
      }
    }
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        filler.push_back(ref_sig_.h[i][k] ? f.one() : f.zero());
      }
    }

    // 3. Witness
    for (size_t i = 0; i < Params::tau; ++i) {
      filler.push_back(j_vals_[i], 8, f);
      filler.push_back(j_k_indices_[i], 16, f);
    }

    Sha3Witness::fill_witness(filler, shake_bws_, f);

    for (size_t s = 0; s < Params::tau; ++s) {
      for (size_t k = 0; k <= s; ++k) {
        filler.push_back(position_trace_[s][k], 8, f);
      }
    }

    for (size_t k = 0; k < ml_dsa::N; ++k)
      filler.push_back(f.of_scalar(c_coeffs_[k]));

    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k)
        filler.push_back(f.of_scalar(w_prime_approx_[i][k]));
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        int32_t val = w1_[i][k];
        if (val < 0) val += ml_dsa::Q;
        filler.push_back(f.of_scalar(val));
      }
      for (size_t j = 0; j < ml_dsa::N; ++j) {
        filler.push_back(w1_bits_[i][j], Params::r1_bits, f);
      }
      for (size_t j = 0; j < ml_dsa::N; ++j)
        filler.push_back(hint_aux_bits_[i][j], Params::r0_bits + 1, f);

      for (size_t k = 0; k < ml_dsa::N; ++k)
        filler.push_back(f.of_scalar(w_prime_1_[i][k]));
      for (size_t j = 0; j < ml_dsa::N; ++j)
        filler.push_back(w_prime_1_bits_[i][j], Params::r1_bits, f);
    }

    for (size_t i = 0; i < Params::L; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k)
        filler.push_back(f.of_scalar(nttz_[i][k]));
    }
    for (size_t k = 0; k < ml_dsa::N; ++k)
      filler.push_back(f.of_scalar(nttc_[k]));

    for (size_t i = 0; i < w1_tilde_.size(); ++i)
      filler.push_back(w1_tilde_[i], 8, f);

    for (size_t i = 0; i < c_prime_tilde_bws_.size(); ++i) {
      Sha3Witness::fill_witness(filler, c_prime_tilde_bws_[i], f);
    }
    filler.push_back(h_sum_bits_, bit_width(Params::omega), f);
  }

  static constexpr size_t bit_width(size_t x) {
    return x == 0 ? 0 : 1 + bit_width(x >> 1);
  }

  bool compute_witness(const std::vector<uint8_t>& pk,
                       const std::vector<uint8_t>& sig,
                       const std::vector<uint8_t>& msg,
                       const std::vector<uint8_t>& ctx) {
    if (ctx.size() > 255) return false;

    // 1. Decode Pk
    auto ref_pk = ml_dsa::pkDecode<Params>(pk);
    ref_pk_ = ref_pk;
    std::copy(pk.begin(), pk.begin() + 32, rho_.begin());
    std::copy(ref_pk.tr.begin(), ref_pk.tr.end(), tr_.begin());

    for (size_t i = 0; i < Params::K; ++i) {
      t1_[i] = ref_pk.t1[i];
    }

    // 2. Decode Sig
    auto maybe_ref_sig = ml_dsa::sigDecode<Params>(sig);
    if (!maybe_ref_sig.has_value()) return false;
    auto ref_sig = maybe_ref_sig.value();
    std::copy(ref_sig.c_tilde.begin(), ref_sig.c_tilde.end(), c_tilde_.begin());
    ref_sig_ = ref_sig;
    msg_ = msg;

    // Z and H handling
    uint64_t h_sum = 0;
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        if (ref_sig.h[i][k]) h_sum++;
      }
    }
    h_sum_bits_ = h_sum;

    for (size_t i = 0; i < Params::L; ++i) {
      ml_dsa::Rq z_poly = ref_sig.z[i];

      for (size_t j = 0; j < ml_dsa::N; ++j) {
        int32_t val =
            static_cast<int32_t>(f_.from_montgomery(z_poly[j]).limb_[0]);
        if (val > (ml_dsa::Q / 2)) {
          val -= ml_dsa::Q;
        }

        int32_t bound = Params::gamma_1 - Params::beta;
        // Shift by bound - 1 to match the circuit's strict inequality check.
        int32_t shifted = val + bound - 1;

        z_bits_[i][j] = static_cast<uint64_t>(shifted);
      }
      nttz_[i] = z_poly;
      ml_dsa::Ntt(nttz_[i]);
    }

    // 3. SampleInBall logic
    c_coeffs_ = ml_dsa::SampleInBall<Params>(c_tilde_);

    // Flattened c for NTT
    nttc_ = c_coeffs_;
    ml_dsa::Ntt(nttc_);

    // witness logic for SampleInBall (SHAKE blocks)
    std::vector<uint8_t> shake_input(c_tilde_.begin(), c_tilde_.end());
    std::vector<Sha3Witness::BlockWitness> temp_bws;
    Sha3Witness::compute_witness_shake256(shake_input, 136, temp_bws);
    shake_bws_ = temp_bws[0];

    // Manual rejecting sampling witness
    std::array<uint8_t, 136> hash_out;
    ml_dsa::H(shake_input, hash_out);

    int count = 0;
    size_t out_idx = 8;
    for (int i = 256 - Params::tau; i < 256; ++i) {
      uint8_t j;
      do {
        // There is a small completeness error, if 136 bytes are not
        // sufficient to generate tau samples, this loop will fail.
        if (out_idx >= hash_out.size()) return false;
        j = hash_out[out_idx++];
      } while (j > i);
      j_vals_[count] = j;
      j_k_indices_[count] = out_idx - 1;
      count++;
    }

    // Compute position trace
    std::vector<uint8_t> current_pos;
    current_pos.reserve(Params::tau);

    for (size_t s = 0; s < Params::tau; ++s) {
      uint8_t j = j_vals_[s];
      uint8_t i = 256 - Params::tau + s;

      for (auto& p : current_pos) {
        if (p == j) {
          p = i;
          break;
        }
      }
      current_pos.push_back(j);
      std::copy(current_pos.begin(), current_pos.end(),
                position_trace_[s].begin());
    }

    // nttt1
    auto scale_factor = f_.of_scalar(1 << 13);
    for (size_t i = 0; i < Params::K; ++i) {
      ml_dsa::Rq t1_scaled = ref_pk.t1[i];
      for (size_t j = 0; j < ml_dsa::N; ++j) {
        f_.mul(t1_scaled[j], scale_factor);
      }
      nttt1_[i] = t1_scaled;
      ml_dsa::Ntt(nttt1_[i]);
    }

    // w_prime_approx
    for (size_t i = 0; i < Params::K; ++i) {
      ml_dsa::Rq diff;
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        auto az = f_.zero();
        for (size_t j = 0; j < Params::L; ++j) {
          auto term = ref_pk.a_hat[i][j][k];
          f_.mul(term, nttz_[j][k]);
          f_.add(az, term);
        }
        auto ct1 = nttc_[k];
        f_.mul(ct1, nttt1_[i][k]);

        diff[k] = az;
        f_.sub(diff[k], ct1);
      }

      w_prime_approx_[i] = diff;
      ml_dsa::InvNtt(w_prime_approx_[i]);
    }

    // 6. Compute Decompose and UseHint witnesses
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t k = 0; k < ml_dsa::N; ++k) {
        auto n = f_.from_montgomery(w_prime_approx_[i][k]).limb_[0];
        int32_t val = static_cast<int32_t>(n);

        auto [r1, r0] = ml_dsa::Decompose<Params>(val);

        bool h_bit = ref_sig.h[i][k];
        w_prime_1_[i][k] = ml_dsa::UseHint<Params>(h_bit, val);

        w1_[i][k] = r1;

        auto normalize = [&](int64_t x) {
          int64_t v = x % static_cast<int64_t>(ml_dsa::Q);
          if (v < 0) v += ml_dsa::Q;
          return static_cast<uint64_t>(v);
        };

        int64_t gamma2 = static_cast<int64_t>(Params::gamma_2);
        int64_t delta =
            static_cast<int64_t>(val) - static_cast<int64_t>(r1) * (2 * gamma2);

        delta = SymmetricReduce(delta);

        uint64_t R = delta + gamma2;
        uint64_t s = (delta > 0) ? 0 : 1;

        uint64_t aux_bits = R | (s << Params::r0_bits);
        hint_aux_bits_[i][k] = normalize(aux_bits);

        w_prime_1_bits_[i][k] = normalize(w_prime_1_[i][k]);
        w1_bits_[i][k] = normalize(w1_[i][k]);
      }
    }

    // 7. Compute w1Encode (needed for mu)
    std::array<ml_dsa::Rq, Params::K> w1_polys;
    for (size_t i = 0; i < Params::K; ++i) {
      for (size_t j = 0; j < ml_dsa::N; ++j) {
        w1_polys[i][j] = f_.of_scalar(w_prime_1_[i][j]);
      }
    }
    w1_tilde_ = ml_dsa::w1Encode<Params>(w1_polys);

    // 8. Compute mu = H(tr || M', 64)
    std::vector<uint8_t> mu_input(tr_.begin(), tr_.end());
    mu_input.push_back(0);  // domain separator
    mu_input.push_back(static_cast<uint8_t>(ctx.size()));
    mu_input.insert(mu_input.end(), ctx.begin(), ctx.end());
    mu_input.insert(mu_input.end(), msg.begin(), msg.end());

    std::array<uint8_t, 64> mu_out;
    ml_dsa::H(mu_input, mu_out);
    std::copy_n(mu_out.begin(), mu_out.size(), mu_.begin());

    // 9. c_prime_tilde = H(mu || w1_tilde, C_TILDE_BYTES)
    std::vector<uint8_t> c_prime_tilde_input(mu_out.begin(), mu_out.end());
    c_prime_tilde_input.insert(c_prime_tilde_input.end(), w1_tilde_.begin(),
                               w1_tilde_.end());

    std::array<uint8_t, Params::c_tilde_bytes> c_prime_tilde_arr;
    ml_dsa::H(c_prime_tilde_input, c_prime_tilde_arr);
    std::copy(c_prime_tilde_arr.begin(), c_prime_tilde_arr.end(),
              c_prime_tilde_.begin());

    Sha3Witness::compute_witness_shake256(
        c_prime_tilde_input, Params::c_tilde_bytes, c_prime_tilde_bws_);

    if (c_tilde_ != c_prime_tilde_) {
      return false;
    }

    return true;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_WITNESS_H_
