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

#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "algebra/fp24.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "circuits/tests/sha3/sha3_reference.h"
#include "util/panic.h"

namespace proofs {
namespace ml_dsa {

// Defined as SHAKE128(str, 8 * len) bits
void G(const std::vector<uint8_t>& in, size_t len, std::vector<uint8_t>& out) {
  out.resize(len);
  Sha3Reference::shake128Hash(in.data(), in.size(), out.data(), len);
}

Rq mulf(Rq a, const Rq& b) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  for (int i = 0; i < 256; ++i) {
    a[i] = Fq.mulf(a[i], b[i]);
  }
  return a;
}

Rq addf(Rq a, const Rq& b) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  for (int i = 0; i < 256; ++i) {
    a[i] = Fq.addf(a[i], b[i]);
  }
  return a;
}

Rq subf(Rq a, const Rq& b) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  for (int i = 0; i < 256; ++i) {
    a[i] = Fq.subf(a[i], b[i]);
  }
  return a;
}

Rq scalef(Rq a, const Elt& s) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  for (int i = 0; i < 256; ++i) {
    a[i] = Fq.mulf(a[i], s);
  }
  return a;
}

// Algorithm 41 NTT(𝑤)
void Ntt(Rq& a) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  const auto& zetas = kZetas;
  int k = 1;
  for (int len = 128; len >= 1; len >>= 1) {
    for (int start = 0; start < 256; start += 2 * len) {
      Elt zeta = Fq.of_scalar(zetas[k++]);
      for (int j = start; j < start + len; ++j) {
        Elt t = Fq.mulf(zeta, a[j + len]);
        a[j + len] = Fq.subf(a[j], t);
        a[j] = Fq.addf(a[j], t);
      }
    }
  }
}

// Algorithm 42 NTT−1(𝑤)̂
// Computes the inverse of the NTT.
void InvNtt(Rq& a) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  const auto& zetas = kZetas;
  int k = 255;
  for (int len = 1; len < 256; len <<= 1) {
    for (int start = 0; start < 256; start += 2 * len) {
      Elt zeta = Fq.negf(Fq.of_scalar(zetas[k--]));
      for (int j = start; j < start + len; ++j) {
        Elt t = a[j];
        a[j] = Fq.addf(t, a[j + len]);
        a[j + len] = Fq.mulf(Fq.subf(t, a[j + len]), zeta);
      }
    }
  }
  // Multiply by 256^-1
  Elt f = Fq.of_scalar(8347681);  // 256^-1 mod 8380417
  for (int i = 0; i < 256; ++i) {
    a[i] = Fq.mulf(a[i], f);
  }
}

Rq RejNTTPoly(const std::vector<uint8_t>& rho, size_t num_blocks) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  std::vector<uint8_t> out;
  // G is SHAKE128, which has a block size of 168 bytes
  size_t extract_len = num_blocks * 168;
  G(rho, extract_len, out);

  Rq a;
  size_t j = 0;
  for (size_t i = 0; i + 2 < out.size() && j < 256; i += 3) {
    uint8_t buf[8] = {0};
    buf[0] = out[i];
    buf[1] = out[i + 1];
    buf[2] = out[i + 2] & 0x7F;
    auto maybe_z = Fq.of_bytes_field(buf);
    if (maybe_z.has_value()) {
      a[j] = maybe_z.value();
      j++;
    }
  }
  check(j >= 256, "Failed to sample polynomial");
  return a;
}

// Algorithm 29 SampleInBall(rho)
// Samples a polynomial c in R with coefficients from {-1, 0, 1} and Hamming
// weight tau.
template <typename Params>
Rq SampleInBall(const std::array<uint8_t, Params::c_tilde_bytes>& rho) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  std::array<uint8_t, 136> out;
  std::vector<uint8_t> rho_vec(rho.begin(), rho.end());
  H(rho_vec, out);

  Rq c;
  for (size_t k = 0; k < N; ++k) {
    c[k] = Fq.zero();
  }

  size_t out_idx = 8;
  for (size_t i = 256 - Params::tau; i < 256; ++i) {
    uint8_t j;
    do {
      check(out_idx < out.size(),
            "SampleInBall: Not enough pseudorandom bytes");
      j = out[out_idx++];
    } while (j > i);

    c[i] = c[j];

    size_t bit_idx = i + Params::tau - 256;
    size_t byte_idx = bit_idx / 8;
    size_t bit_shift = bit_idx % 8;
    uint8_t bit = (out[byte_idx] >> bit_shift) & 1;

    if (bit == 1) {
      c[j] = Fq.mone();
    } else {
      c[j] = Fq.one();
    }
  }
  return c;
}

// Algorithm 32 ExpandA(rho)
// Samples a K x L matrix A_hat of elements of T_q.
// Input: A seed rho (32 bytes).
// Output: Matrix A_hat in (T_q)^(K x L).
template <typename Params>
typename MLDsaTypes<Params>::MatrixA ExpandA(const std::vector<uint8_t>& rho) {
  typename MLDsaTypes<Params>::MatrixA A_hat;
  for (uint8_t r = 0; r < Params::K; ++r) {
    for (uint8_t s = 0; s < Params::L; ++s) {
      std::vector<uint8_t> rho_prime = rho;
      // IntegerToBytes(s, 1) || IntegerToBytes(r, 1)
      // Little-endian
      rho_prime.push_back(s);
      rho_prime.push_back(r);
      // Samples a polynomial in T_q. Using 5 blocks (168 * 5 = 840 bytes)
      // should be overwhelmingly sufficient for rejection sampling 256
      // coefficients.
      A_hat[r][s] = RejNTTPoly(rho_prime, 5);
    }
  }
  return A_hat;
}

template <typename Params>
std::pair<int32_t, int32_t> Decompose(int32_t r) {
  // Handle the case that r < 0 or r > q by
  // normalizing r_plus in the range [0, q-1].
  int32_t r_plus = r % static_cast<int32_t>(ml_dsa::Q);
  if (r_plus < 0) {
    r_plus += static_cast<int32_t>(ml_dsa::Q);
  }

  const int32_t alpha = 2 * Params::gamma_2;
  const int32_t half_alpha = alpha / 2;
  int32_t r0 = r_plus % alpha;
  if (r0 > half_alpha) {
    r0 -= alpha;
  }

  int32_t r1;
  if (r_plus - r0 == ml_dsa::Q - 1) {
    r1 = 0;
    r0 = r0 - 1;
  } else {
    r1 = (r_plus - r0) / alpha;
  }
  return {r1, r0};
}

template <typename Params>
uint32_t UseHint(bool h, int32_t r) {
  const int32_t m = (ml_dsa::Q - 1) / (2 * Params::gamma_2);
  auto [r1, r0] = Decompose<Params>(r);

  if (h && r0 > 0) {
    return (r1 + 1) % m;
  }
  if (h && r0 <= 0) {
    int32_t res = (r1 - 1) % m;
    if (res < 0) res += m;
    return res;
  }
  return r1;
}

// Algorithm 19 BitUnpack(v, a, b)
std::optional<Rq> BitUnpack(const std::vector<uint8_t>& v, uint32_t a,
                            uint32_t b, uint32_t c) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  Rq w;
  if (v.size() != 32 * c) return std::nullopt;

  // Reversing the BitPack procedure
  // Extract c bits at a time
  for (size_t i = 0; i < N; ++i) {
    size_t bit_offset = i * c;
    size_t byte_offset = bit_offset / 8;
    size_t shift = bit_offset % 8;

    uint32_t val = 0;
    // We need c bits. This will touch at most 4 bytes.
    for (size_t k = 0; k < 4 && byte_offset + k < v.size(); ++k) {
      val |= (static_cast<uint32_t>(v[byte_offset + k]) << (8 * k));
    }

    val >>= shift;
    val &= ((1 << c) - 1);  // Mask out c bits

    // w_i = b - val
    int32_t wi = b - val;
    // Map to [0, q-1]
    if (wi < 0) {
      wi += ml_dsa::Q;
    }
    w[i] = Fq.of_scalar(wi);
  }
  return w;
}

// Algorithm 21 HintBitUnpack(y)
template <typename Params>
std::optional<std::array<std::array<bool, N>, Params::K>> HintBitUnpack(
    const std::vector<uint8_t>& y) {
  std::array<std::array<bool, N>, Params::K> h = {};
  for (size_t i = 0; i < Params::K; ++i) {
    for (size_t j = 0; j < N; ++j) {
      h[i][j] = false;
    }
  }

  size_t index = 0;
  for (size_t i = 0; i < Params::K; ++i) {
    int limit = y[Params::omega + i];
    if (limit < index || limit > Params::omega) return std::nullopt;

    int last = -1;
    while (index < limit) {
      int byte = y[index++];
      if (last >= 0 && byte <= last) {
        return std::nullopt;
      }
      last = byte;
      h[i][byte] = true;
    }
  }
  for (; index < Params::omega; ++index) {
    if (y[index] != 0) {
      return std::nullopt;
    }
  }

  return h;
}

// Algorithm 27 sigDecode(sigma)
template <typename Params>
std::optional<typename MLDsaTypes<Params>::Signature> sigDecode(
    const std::vector<uint8_t>& sigma) {
  typename MLDsaTypes<Params>::Signature sig;

  constexpr size_t c = Params::z_coeff_bits;
  size_t expected_size =
      Params::c_tilde_bytes + Params::L * 32 * c + Params::omega + Params::K;
  if (sigma.size() < expected_size) return std::nullopt;

  size_t offset = 0;

  // 1. Extract c_tilde
  std::copy(sigma.begin() + offset,
            sigma.begin() + offset + Params::c_tilde_bytes,
            sig.c_tilde.begin());
  offset += Params::c_tilde_bytes;

  // 2. Extract z_i
  size_t z_bytes = 32 * c;
  for (size_t i = 0; i < Params::L; ++i) {
    std::vector<uint8_t> v(sigma.begin() + offset,
                           sigma.begin() + offset + z_bytes);
    auto maybe_z = BitUnpack(v, Params::gamma_1 - 1, Params::gamma_1, c);
    if (!maybe_z.has_value()) return std::nullopt;
    sig.z[i] = maybe_z.value();
    offset += z_bytes;
  }

  // 3. Extract h
  std::vector<uint8_t> y(sigma.begin() + offset,
                         sigma.begin() + offset + Params::omega + Params::K);
  auto maybe_h = HintBitUnpack<Params>(y);
  if (!maybe_h.has_value()) return std::nullopt;
  sig.h = maybe_h.value();
  offset += Params::omega + Params::K;

  return sig;
}

// Algorithm 18 SimpleBitUnpack(v, b)
// Extracts coefficients from a byte array.
Rq SimpleBitUnpack(const std::vector<uint8_t>& v, uint32_t b) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  Rq w;
  uint32_t c = bitlen(b);
  check(v.size() == 32 * c, "SimpleBitUnpack input size mismatch");

  // Extract c bits at a time
  for (size_t i = 0; i < N; ++i) {
    size_t bit_offset = i * c;
    size_t byte_offset = bit_offset / 8;
    size_t shift = bit_offset % 8;

    uint32_t val = 0;
    // We need c bits. This will touch at most 2 bytes.
    for (size_t k = 0; k < 2 && byte_offset + k < v.size(); ++k) {
      val |= (static_cast<uint32_t>(v[byte_offset + k]) << (8 * k));
    }

    val >>= shift;
    val &= ((1 << c) - 1);  // Mask out c bits

    w[i] = Fq.of_scalar(val);
  }
  return w;
}

// Algorithm 23 pkDecode(pk)
// Reverses the procedure pkEncode, expanding rho to a_hat and unpacking t1.
template <typename Params>
typename MLDsaTypes<Params>::PublicKey pkDecode(
    const std::vector<uint8_t>& pk) {
  typename MLDsaTypes<Params>::PublicKey pub_key;

  // pk is 32 + 32 * K * c bytes where c = 10
  constexpr size_t c = 10;
  size_t expected_size = 32 + 32 * Params::K * c;
  check(pk.size() >= expected_size, "pkDecode public key too short");

  size_t offset = 0;

  // 1. Extract rho
  std::vector<uint8_t> rho(pk.begin() + offset, pk.begin() + offset + 32);
  offset += 32;

  // 2. Expand a_hat from rho
  pub_key.a_hat = ExpandA<Params>(rho);

  // 3. Extract t1
  size_t t1_bytes = 32 * c;
  for (size_t i = 0; i < Params::K; ++i) {
    std::vector<uint8_t> v(pk.begin() + offset, pk.begin() + offset + t1_bytes);
    pub_key.t1[i] = SimpleBitUnpack(v, 1023);
    offset += t1_bytes;
  }

  // 4. Compute tr = SHAKE256(pk, 64)
  H(pk, pub_key.tr);

  return pub_key;
}

// Algorithm 18 SimpleBitPack(w, b)
std::vector<uint8_t> SimpleBitPack(const Rq& w, uint32_t b) {
  const Fp24& Fq = proofs::ml_dsa::Fq();
  // Determine bitlen
  uint32_t bitlen = 0;
  uint32_t val = b;
  while (val > 0) {
    bitlen++;
    val >>= 1;
  }
  if (b == 0) bitlen = 1;

  // Total bits = 256 * bitlen
  // Total bytes = ceil(Total bits / 8)
  size_t total_bits = 256 * bitlen;
  size_t total_bytes = (total_bits + 7) / 8;
  std::vector<uint8_t> z(total_bytes, 0);

  size_t current_bit = 0;
  for (size_t i = 0; i < N; ++i) {
    // Assuming w[i] is already reduced and positive.
    // Use Fq.from_montgomery(w[i]) to get canonical representation.
    uint64_t wi_long = Fq.from_montgomery(w[i]).limb_[0];
    uint32_t wi = static_cast<uint32_t>(wi_long);

    // Should verify wi <= b, but input assumes it is.

    for (size_t k = 0; k < bitlen; ++k) {
      if ((wi >> k) & 1) {
        size_t byte_idx = current_bit / 8;
        size_t bit_idx = current_bit % 8;
        z[byte_idx] |= (1 << bit_idx);
      }
      current_bit++;
    }
  }
  return z;
}

template <typename Params>
std::array<uint8_t, Params::K * Params::w1_bytes> w1Encode(
    const typename MLDsaTypes<Params>::RqK& w1) {
  std::array<uint8_t, Params::K * Params::w1_bytes> w1_tilde;
  const uint32_t b = (ml_dsa::Q - 1) / (2 * Params::gamma_2) - 1;

  size_t offset = 0;
  for (size_t i = 0; i < Params::K; ++i) {
    std::vector<uint8_t> packed = SimpleBitPack(w1[i], b);
    std::copy(packed.begin(), packed.end(), w1_tilde.begin() + offset);
    offset += packed.size();
  }
  return w1_tilde;
}

std::optional<std::vector<uint8_t>> preprocess_message(
    const std::vector<uint8_t>& msg, const std::vector<uint8_t>& ctx) {
  if (ctx.size() > 255) return std::nullopt;
  std::vector<uint8_t> res;
  res.reserve(2 + ctx.size() + msg.size());
  res.push_back(0);
  res.push_back(static_cast<uint8_t>(ctx.size()));
  res.insert(res.end(), ctx.begin(), ctx.end());
  res.insert(res.end(), msg.begin(), msg.end());
  return res;
}

// Explicit instantiations for ML-DSA-44 and ML-DSA-65
template Rq SampleInBall<MLDsa44Params>(
    const std::array<uint8_t, MLDsa44Params::c_tilde_bytes>& rho);
template Rq SampleInBall<MLDsa65Params>(
    const std::array<uint8_t, MLDsa65Params::c_tilde_bytes>& rho);

template MLDsaTypes<MLDsa44Params>::MatrixA ExpandA<MLDsa44Params>(
    const std::vector<uint8_t>& rho);
template MLDsaTypes<MLDsa65Params>::MatrixA ExpandA<MLDsa65Params>(
    const std::vector<uint8_t>& rho);

template std::pair<int32_t, int32_t> Decompose<MLDsa44Params>(int32_t r);
template std::pair<int32_t, int32_t> Decompose<MLDsa65Params>(int32_t r);

template uint32_t UseHint<MLDsa44Params>(bool h, int32_t r);
template uint32_t UseHint<MLDsa65Params>(bool h, int32_t r);

template std::optional<std::array<std::array<bool, N>, MLDsa44Params::K>>
HintBitUnpack<MLDsa44Params>(const std::vector<uint8_t>& y);
template std::optional<std::array<std::array<bool, N>, MLDsa65Params::K>>
HintBitUnpack<MLDsa65Params>(const std::vector<uint8_t>& y);

template std::optional<MLDsaTypes<MLDsa44Params>::Signature>
sigDecode<MLDsa44Params>(const std::vector<uint8_t>& sigma);
template std::optional<MLDsaTypes<MLDsa65Params>::Signature>
sigDecode<MLDsa65Params>(const std::vector<uint8_t>& sigma);

template MLDsaTypes<MLDsa44Params>::PublicKey pkDecode<MLDsa44Params>(
    const std::vector<uint8_t>& pk);
template MLDsaTypes<MLDsa65Params>::PublicKey pkDecode<MLDsa65Params>(
    const std::vector<uint8_t>& pk);

template std::array<uint8_t, MLDsa44Params::K * MLDsa44Params::w1_bytes>
w1Encode<MLDsa44Params>(const MLDsaTypes<MLDsa44Params>::RqK& w1);
template std::array<uint8_t, MLDsa65Params::K * MLDsa65Params::w1_bytes>
w1Encode<MLDsa65Params>(const MLDsaTypes<MLDsa65Params>::RqK& w1);

}  // namespace ml_dsa
}  // namespace proofs
