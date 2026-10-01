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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_SHARED_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_SHARED_H_

#include <array>
#include <cstddef>
#include <cstdint>

#include "algebra/fp24.h"

namespace proofs {
namespace ml_dsa {

constexpr size_t bitlen(uint64_t val) {
  return val == 0 ? 0 : 1 + bitlen(val >> 1);
}

// q: 2^23 - 2^13 + 1 = 8380417.
static constexpr uint32_t Q = 8380417;
using Elt = Fp24::Elt;
static constexpr size_t N = 256;
static constexpr uint64_t D = 13;
const Fp24& Fq();

using Rq = std::array<Elt, N>;

inline constexpr uint64_t kZetas[256] = {
    1u,       4808194u, 3765607u, 3761513u, 5178923u, 5496691u, 5234739u,
    5178987u, 7778734u, 3542485u, 2682288u, 2129892u, 3764867u, 7375178u,
    557458u,  7159240u, 5010068u, 4317364u, 2663378u, 6705802u, 4855975u,
    7946292u, 676590u,  7044481u, 5152541u, 1714295u, 2453983u, 1460718u,
    7737789u, 4795319u, 2815639u, 2283733u, 3602218u, 3182878u, 2740543u,
    4793971u, 5269599u, 2101410u, 3704823u, 1159875u, 394148u,  928749u,
    1095468u, 4874037u, 2071829u, 4361428u, 3241972u, 2156050u, 3415069u,
    1759347u, 7562881u, 4805951u, 3756790u, 6444618u, 6663429u, 4430364u,
    5483103u, 3192354u, 556856u,  3870317u, 2917338u, 1853806u, 3345963u,
    1858416u, 3073009u, 1277625u, 5744944u, 3852015u, 4183372u, 5157610u,
    5258977u, 8106357u, 2508980u, 2028118u, 1937570u, 4564692u, 2811291u,
    5396636u, 7270901u, 4158088u, 1528066u, 482649u,  1148858u, 5418153u,
    7814814u, 169688u,  2462444u, 5046034u, 4213992u, 4892034u, 1987814u,
    5183169u, 1736313u, 235407u,  5130263u, 3258457u, 5801164u, 1787943u,
    5989328u, 6125690u, 3482206u, 4197502u, 7080401u, 6018354u, 7062739u,
    2461387u, 3035980u, 621164u,  3901472u, 7153756u, 2925816u, 3374250u,
    1356448u, 5604662u, 2683270u, 5601629u, 4912752u, 2312838u, 7727142u,
    7921254u, 348812u,  8052569u, 1011223u, 6026202u, 4561790u, 6458164u,
    6143691u, 1744507u, 1753u,    6444997u, 5720892u, 6924527u, 2660408u,
    6600190u, 8321269u, 2772600u, 1182243u, 87208u,   636927u,  4415111u,
    4423672u, 6084020u, 5095502u, 4663471u, 8352605u, 822541u,  1009365u,
    5926272u, 6400920u, 1596822u, 4423473u, 4620952u, 6695264u, 4969849u,
    2678278u, 4611469u, 4829411u, 635956u,  8129971u, 5925040u, 4234153u,
    6607829u, 2192938u, 6653329u, 2387513u, 4768667u, 8111961u, 5199961u,
    3747250u, 2296099u, 1239911u, 4541938u, 3195676u, 2642980u, 1254190u,
    8368000u, 2998219u, 141835u,  8291116u, 2513018u, 7025525u, 613238u,
    7070156u, 6161950u, 7921677u, 6458423u, 4040196u, 4908348u, 2039144u,
    6500539u, 7561656u, 6201452u, 6757063u, 2105286u, 6006015u, 6346610u,
    586241u,  7200804u, 527981u,  5637006u, 6903432u, 1994046u, 2491325u,
    6987258u, 507927u,  7192532u, 7655613u, 6545891u, 5346675u, 8041997u,
    2647994u, 3009748u, 5767564u, 4148469u, 749577u,  4357667u, 3980599u,
    2569011u, 6764887u, 1723229u, 1665318u, 2028038u, 1163598u, 5011144u,
    3994671u, 8368538u, 7009900u, 3020393u, 3363542u, 214880u,  545376u,
    7609976u, 3105558u, 7277073u, 508145u,  7826699u, 860144u,  3430436u,
    140244u,  6866265u, 6195333u, 3123762u, 2358373u, 6187330u, 5365997u,
    6663603u, 2926054u, 7987710u, 8077412u, 3531229u, 4405932u, 4606686u,
    1900052u, 7598542u, 1054478u, 7648983u,
};

// ML-DSA parameter sets.
// The ML-DSA algorithms are specified in FIPS 204:
// https://nvlpubs.nist.gov/nistPubs/fips/nist.fips.204.pdf
//
// The parameter values below are sourced from Section 4, Table 1, page 15.
template <size_t K_val, size_t L_val, size_t tau_val, size_t omega_val,
          size_t c_tilde_bytes_val, uint64_t gamma_1_val, uint64_t gamma_2_val,
          uint64_t beta_val, size_t z_bits_val, size_t r1_bits_val,
          size_t w1_bytes_val>
struct MLDsaParams {
  static constexpr size_t K = K_val;          // Dimension of matrix A (rows)
  static constexpr size_t L = L_val;          // Dimension of matrix A (columns)
  static constexpr size_t tau = tau_val;      // Number of +/-1 in challenge c
  static constexpr size_t omega = omega_val;  // Max number of ones in hint h
  static constexpr size_t c_tilde_bytes =
      c_tilde_bytes_val;  // Hash commitment size in bytes (2*lambda bits)
  static constexpr uint64_t gamma_1 = gamma_1_val;  // Coefficient range of y
  static constexpr uint64_t gamma_2 = gamma_2_val;  // Low-order rounding range
  static constexpr uint64_t beta = beta_val;  // tau * eta (rejection bound)
  static constexpr size_t z_bits =
      z_bits_val;  // Bits to pack z coefficients (circuit representation)
  static constexpr size_t r1_bits = r1_bits_val;  // Bits for w1 coefficient
  static constexpr size_t w1_bytes =
      w1_bytes_val;  // Bytes to encode one w1 polynomial

  // Derived parameters
  static constexpr size_t z_coeff_bits = bitlen(2 * gamma_1 - 1);
  static constexpr size_t r0_bits =
      (gamma_2 == 95232) ? 18 : 19;  // Bits for r0 remainder
  static constexpr size_t M =
      (Q - 1) / (2 * gamma_2);  // Congruence modulo M for UseHint (44 or 16)
};

// ML-DSA-44 parameters (FIPS 204 Section 4, Table 1)
using MLDsa44Params =
    MLDsaParams<4, 4, 39, 80, 32, 131072, 95232, 78, 19, 6, 192>;

// ML-DSA-65 parameters (FIPS 204 Section 4, Table 1)
using MLDsa65Params =
    MLDsaParams<6, 5, 49, 55, 48, 524288, 261888, 196, 20, 4, 128>;

template <typename Params>
struct MLDsaTypes {
  using RqK = std::array<Rq, Params::K>;
  using RqL = std::array<Rq, Params::L>;
  using MatrixA = std::array<RqL, Params::K>;

  struct PublicKey {
    MatrixA a_hat;
    RqK t1;
    std::array<uint8_t, 64> tr;
  };

  struct Signature {
    std::array<uint8_t, Params::c_tilde_bytes> c_tilde;
    RqL z;
    std::array<std::array<bool, N>, Params::K> h;
  };
};

}  // namespace ml_dsa
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_ML_DSA_ML_DSA_SHARED_H_
