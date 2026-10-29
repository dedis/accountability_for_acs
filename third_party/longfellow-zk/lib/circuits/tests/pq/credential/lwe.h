// Module-LWE encryption of the CFT identity and its
// circuit over an extension of Fq, q = 8380417 (not upstream).
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!  Experimental research code.
//
// The parameters mirror the Module-LWE instance of ML-DSA at the same q:
// rank K = 5 and secrets and errors uniform in [-ETA, ETA] with ETA = 4 for
// category 3 (ML-DSA-65: l = 5, eta = 4), K = 7 and ETA = 2 for category 5
// (ML-DSA-87: l = 7, eta = 2). The ciphertext gives K + 3 samples of the
// secret R (ML-DSA: k = 6 or 8). tools/lwe_estimate.py (repository root)
// checks them with the lattice estimator.
//
// Not constant-time: this is the reference of the tests and benchmarks.
// crates/pqc/src/lwe.rs is the constant-time implementation.
//
// Ring R_q = Z_q[X] / (X^256 + 1). Public matrix A (K x K, NTT domain,
// RejNTTPoly of a public seed, as ML-DSA's ExpandA). Key: three slots
// T_j = A S_j + E_j (j < 3), the sum of the shares of the three
// authorities. The message M is 768 bits, one bit per coefficient of three
// polynomials: ID (64 bytes) || R2 (32 bytes), bit i of byte b at 8 b + i.
//
//   U   = A^T R + E1                    (K polynomials)
//   V_j = T_j^T R + E2_j + floor(q / 2) M_j   (3 polynomials)
//
// with R, E1 in S_ETA^K and E2 in S_ETA^3. The circuit proves this
// relation for public (U, V), a private M and private small R, E1, E2.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_LWE_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_LWE_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "arrays/packed_layer.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_ref.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_shared.h"
#include "random/random.h"
#include "util/panic.h"

namespace proofs {
namespace pq_cred {

constexpr size_t kLweSlots = 3;
constexpr size_t kLweMsgBytes = kLweSlots * ml_dsa::N / 8;  // 96

template <size_t kK, uint32_t kEta>
struct LweParams {
  static constexpr size_t K = kK;
  static constexpr uint32_t eta = kEta;
};
using LweCategory3 = LweParams<5, 4>;
using LweCategory5 = LweParams<7, 2>;

// Integer polynomials, coefficients in [0, q).
using Poly = std::array<uint32_t, ml_dsa::N>;

inline uint32_t from_elt(const ml_dsa::Elt& e) {
  return static_cast<uint32_t>(ml_dsa::Fq().from_montgomery(e).limb_[0]);
}
inline ml_dsa::Elt to_elt(uint32_t x) { return ml_dsa::Fq().of_scalar(x); }

inline ml_dsa::Rq to_rq(const Poly& p) {
  ml_dsa::Rq r;
  for (size_t i = 0; i < ml_dsa::N; ++i) r[i] = to_elt(p[i]);
  return r;
}
inline Poly to_poly(const ml_dsa::Rq& r) {
  Poly p;
  for (size_t i = 0; i < ml_dsa::N; ++i) p[i] = from_elt(r[i]);
  return p;
}

template <class LP>
struct LwePublic {
  std::array<std::array<ml_dsa::Rq, LP::K>, LP::K> a_hat;  // [row][col]
  std::array<std::array<ml_dsa::Rq, LP::K>, kLweSlots> t_hat;
};

template <class LP>
struct LweSecret {
  std::array<std::array<Poly, LP::K>, kLweSlots> s;
};

template <class LP>
struct LweCiphertext {
  std::array<Poly, LP::K> u;
  std::array<Poly, kLweSlots> v;
};

// The encryption randomness, the witness of the circuit.
template <class LP>
struct LweRandomness {
  std::array<Poly, LP::K> r, e1;
  std::array<Poly, kLweSlots> e2;
};

template <class LP>
class Lwe {
  static constexpr uint32_t Q = ml_dsa::Q;

 public:
  // A uniform in [-eta, eta], as an integer in [0, q). At most 4 of 256
  // bytes are rejected: 32 rejections in a row occur with probability below
  // 2^-192.
  static uint32_t small(RandomEngine& rng) {
    for (int draw = 0; draw < 32; ++draw) {
      uint8_t x;
      rng.bytes(&x, 1);
      if (x < 256 - 256 % (2 * LP::eta + 1)) {
        const uint32_t v = x % (2 * LP::eta + 1);
        return v <= LP::eta ? v : Q - (2 * LP::eta + 1 - v);
      }
    }
    check(false, "the random engine gave 32 rejected bytes in a row");
    return 0;
  }

  static Poly small_poly(RandomEngine& rng) {
    Poly p;
    for (auto& c : p) c = small(rng);
    return p;
  }

  // The public matrix from SEED (32 bytes), and a random key.
  static void keygen(const std::array<uint8_t, 32>& seed, RandomEngine& rng,
                     LwePublic<LP>& pub, LweSecret<LP>& sec) {
    std::array<std::array<Poly, LP::K>, kLweSlots> e;
    for (size_t j = 0; j < kLweSlots; ++j) {
      for (Poly& s : sec.s[j]) s = small_poly(rng);
      for (Poly& p : e[j]) p = small_poly(rng);
    }
    keygen(seed, sec, e, pub);
  }

  // The public matrix from SEED and the key of the secret SEC and the error
  // E: T_j = A S_j + E_j.
  static void keygen(const std::array<uint8_t, 32>& seed,
                     const LweSecret<LP>& sec,
                     const std::array<std::array<Poly, LP::K>, kLweSlots>& e,
                     LwePublic<LP>& pub) {
    for (uint8_t i = 0; i < LP::K; ++i) {
      for (uint8_t j = 0; j < LP::K; ++j) {
        std::vector<uint8_t> in(seed.begin(), seed.end());
        in.push_back(j);
        in.push_back(i);
        pub.a_hat[i][j] = ml_dsa::RejNTTPoly(in, 5);
      }
    }
    for (size_t j = 0; j < kLweSlots; ++j) {
      std::array<ml_dsa::Rq, LP::K> s_hat;
      for (size_t c = 0; c < LP::K; ++c) {
        s_hat[c] = to_rq(sec.s[j][c]);
        ml_dsa::Ntt(s_hat[c]);
      }
      for (size_t i = 0; i < LP::K; ++i) {
        ml_dsa::Rq acc = to_rq(Poly{});
        for (size_t c = 0; c < LP::K; ++c) {
          acc = ml_dsa::addf(acc, ml_dsa::mulf(pub.a_hat[i][c], s_hat[c]));
        }
        ml_dsa::Rq e_hat = to_rq(e[j][i]);
        ml_dsa::Ntt(e_hat);
        pub.t_hat[j][i] = ml_dsa::addf(acc, e_hat);
      }
    }
  }

  // Encrypts M with random RND.
  static LweCiphertext<LP> encrypt(const LwePublic<LP>& pub,
                                   const std::array<uint8_t, kLweMsgBytes>& m,
                                   RandomEngine& rng, LweRandomness<LP>& rnd) {
    for (size_t c = 0; c < LP::K; ++c) {
      rnd.r[c] = small_poly(rng);
      rnd.e1[c] = small_poly(rng);
    }
    for (Poly& p : rnd.e2) p = small_poly(rng);
    return encrypt(pub, m, rnd);
  }

  // Encrypts M with the randomness RND.
  static LweCiphertext<LP> encrypt(const LwePublic<LP>& pub,
                                   const std::array<uint8_t, kLweMsgBytes>& m,
                                   const LweRandomness<LP>& rnd) {
    std::array<ml_dsa::Rq, LP::K> r_hat;
    for (size_t c = 0; c < LP::K; ++c) {
      r_hat[c] = to_rq(rnd.r[c]);
      ml_dsa::Ntt(r_hat[c]);
    }
    LweCiphertext<LP> ct;
    for (size_t i = 0; i < LP::K; ++i) {
      ml_dsa::Rq acc = to_rq(Poly{});
      for (size_t c = 0; c < LP::K; ++c) {
        acc = ml_dsa::addf(acc, ml_dsa::mulf(pub.a_hat[c][i], r_hat[c]));
      }
      ml_dsa::InvNtt(acc);
      ct.u[i] = to_poly(ml_dsa::addf(acc, to_rq(rnd.e1[i])));
    }
    for (size_t j = 0; j < kLweSlots; ++j) {
      ml_dsa::Rq acc = to_rq(Poly{});
      for (size_t c = 0; c < LP::K; ++c) {
        acc = ml_dsa::addf(acc, ml_dsa::mulf(pub.t_hat[j][c], r_hat[c]));
      }
      ml_dsa::InvNtt(acc);
      Poly v = to_poly(ml_dsa::addf(acc, to_rq(rnd.e2[j])));
      for (size_t t = 0; t < ml_dsa::N; ++t) {
        if (bit(m, j, t)) v[t] = static_cast<uint32_t>((v[t] + Q / 2) % Q);
      }
      ct.v[j] = v;
    }
    return ct;
  }

  // Decryption with the summed key: M_j = round(2 (V_j - S_j^T U) / q).
  static std::array<uint8_t, kLweMsgBytes> decrypt(const LweSecret<LP>& sec,
                                                   const LweCiphertext<LP>& ct) {
    std::array<uint8_t, kLweMsgBytes> m{};
    for (size_t j = 0; j < kLweSlots; ++j) {
      ml_dsa::Rq acc = to_rq(Poly{});
      for (size_t c = 0; c < LP::K; ++c) {
        ml_dsa::Rq s = to_rq(sec.s[j][c]), u = to_rq(ct.u[c]);
        ml_dsa::Ntt(s);
        ml_dsa::Ntt(u);
        acc = ml_dsa::addf(acc, ml_dsa::mulf(s, u));
      }
      ml_dsa::InvNtt(acc);
      const Poly w = to_poly(ml_dsa::subf(to_rq(ct.v[j]), acc));
      for (size_t t = 0; t < ml_dsa::N; ++t) {
        // 1 if w is closer to q/2 than to 0.
        const bool one = w[t] > Q / 4 && w[t] < Q - Q / 4;
        const size_t i = j * ml_dsa::N + t;
        m[i / 8] |= uint8_t(one) << (i % 8);
      }
    }
    return m;
  }

  static bool bit(const std::array<uint8_t, kLweMsgBytes>& m, size_t j,
                  size_t t) {
    const size_t i = j * ml_dsa::N + t;
    return (m[i / 8] >> (i % 8)) & 1;
  }
};

// Every coefficient of CT is below q. A verifier rejects other ciphertexts
// before it reads them as field elements (of_scalar aborts on them).
template <class LP>
bool in_range(const LweCiphertext<LP>& ct) {
  for (const Poly& p : ct.u) {
    for (uint32_t x : p) {
      if (x >= ml_dsa::Q) return false;
    }
  }
  for (const Poly& p : ct.v) {
    for (uint32_t x : p) {
      if (x >= ml_dsa::Q) return false;
    }
  }
  return true;
}

// Number transform of P (FIPS 204, Algorithm 41), on circuit values.
template <class LogicCircuit>
std::array<typename LogicCircuit::EltW, ml_dsa::N> ntt_circuit(
    const LogicCircuit& lc,
    std::array<typename LogicCircuit::EltW, ml_dsa::N> p) {
  size_t k = 1;
  for (size_t length = ml_dsa::N / 2; length > 0; length /= 2) {
    for (size_t start = 0; start < ml_dsa::N; start += 2 * length) {
      const auto zeta = lc.f_.of_scalar_field(ml_dsa::kZetas[k++]);
      const auto neg_zeta = lc.f_.negf(zeta);
      for (size_t j = start; j < start + length; ++j) {
        const auto t = lc.axpy(p[j], zeta, p[j + length]);
        p[j + length] = lc.axpy(p[j], neg_zeta, p[j + length]);
        p[j] = t;
      }
    }
  }
  return p;
}

// The encryption relation for the public key PUB (circuit constants).
template <class LogicCircuit, class LP>
class LweCircuit {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using PolyW = std::array<EltW, ml_dsa::N>;

 public:
  // Private input offsets, from the first private input.
  static constexpr size_t kMsg = 0;
  static constexpr size_t kR = kMsg + 8 * kLweMsgBytes;
  static constexpr size_t kE1 = kR + LP::K * ml_dsa::N;
  static constexpr size_t kE2 = kE1 + LP::K * ml_dsa::N;
  static constexpr size_t kNPriv = kE2 + kLweSlots * ml_dsa::N;
  // Public inputs: the constant one, U, V.
  static constexpr size_t kNPub = 1 + (LP::K + kLweSlots) * ml_dsa::N;

  struct Public {
    std::array<PolyW, LP::K> u;
    std::array<PolyW, kLweSlots> v;
    void input(const LogicCircuit& lc) {
      for (auto& p : u) for (auto& x : p) x = lc.eltw_input();
      for (auto& p : v) for (auto& x : p) x = lc.eltw_input();
    }
  };

  struct Private {
    std::array<BitW, 8 * kLweMsgBytes> m;
    std::array<PolyW, LP::K> r, e1;
    std::array<PolyW, kLweSlots> e2;
    void input(const LogicCircuit& lc) {
      for (auto& b : m) b = lc.input();
      for (auto& p : r) for (auto& x : p) x = lc.eltw_input();
      for (auto& p : e1) for (auto& x : p) x = lc.eltw_input();
      for (auto& p : e2) for (auto& x : p) x = lc.eltw_input();
    }
  };

  LweCircuit(const LogicCircuit& lc, const LwePublic<LP>& pub)
      : lc_(lc), pub_(pub) {}

  void assert_encryption(const Public& u, const Private& w) const {
    for (const auto& p : w.r) assert_small(p);
    for (const auto& p : w.e1) assert_small(p);
    for (const auto& p : w.e2) assert_small(p);

    // In the NTT domain: NTT(U_i - E1_i) = sum_c A[c][i] o NTT(R_c), and
    // NTT(V_j - E2_j - floor(q/2) M_j) = sum_c T_j[c] o NTT(R_c). NTT is a
    // bijection, so this is the relation above. Only forward NTTs, which
    // stay layered (an inverse NTT merges into one dense layer).
    std::array<PolyW, LP::K> r_hat;
    for (size_t c = 0; c < LP::K; ++c) r_hat[c] = ntt_circuit(lc_, w.r[c]);

    for (size_t i = 0; i < LP::K; ++i) {
      PolyW d;
      for (size_t t = 0; t < ml_dsa::N; ++t) d[t] = lc_.sub(u.u[i][t], w.e1[i][t]);
      assert_eq(ntt_circuit(lc_, d),
                product(r_hat, [&](size_t c) { return &pub_.a_hat[c][i]; }));
    }
    const auto mhalf = lc_.f_.negf(lc_.f_.of_scalar(ml_dsa::Q / 2));
    for (size_t j = 0; j < kLweSlots; ++j) {
      PolyW d;
      for (size_t t = 0; t < ml_dsa::N; ++t) {
        const EltW m = lc_.eval(w.m[j * ml_dsa::N + t]);
        d[t] = lc_.axpy(lc_.sub(u.v[j][t], w.e2[j][t]), mhalf, m);
      }
      assert_eq(ntt_circuit(lc_, d),
                product(r_hat, [&](size_t c) { return &pub_.t_hat[j][c]; }));
    }
  }

 private:
  // sum_c COEF(c) o R_HAT[c], with constant NTT-domain coefficients.
  template <class Coef>
  PolyW product(const std::array<PolyW, LP::K>& r_hat, const Coef& coef) const {
    PolyW s;
    for (size_t t = 0; t < ml_dsa::N; ++t) s[t] = lc_.konst(lc_.f_.zero());
    for (size_t c = 0; c < LP::K; ++c) {
      const ml_dsa::Rq& k = *coef(c);
      for (size_t t = 0; t < ml_dsa::N; ++t) {
        s[t] = lc_.axpy(s[t], lc_.f_.of_scalar_field(k[t]), r_hat[c][t]);
      }
    }
    return s;
  }

  void assert_eq(const PolyW& a, const PolyW& b) const {
    for (size_t t = 0; t < ml_dsa::N; ++t) lc_.assert_eq(a[t], b[t]);
  }

  // Every coefficient of P is in [-eta, eta]: x prod_{t=1}^{eta} (x^2 - t^2)
  // is zero.
  void assert_small(const PolyW& p) const {
    for (const EltW& x : p) {
      const EltW x2 = lc_.mul(x, x);
      EltW prod = x;
      for (uint32_t t = 1; t <= LP::eta; ++t) {
        prod = lc_.mul(prod, lc_.sub(x2, lc_.konst(lc_.f_.of_scalar(t * t))));
      }
      lc_.assert0(prod);
    }
  }

  const LogicCircuit& lc_;
  const LwePublic<LP>& pub_;
};

// The inputs of the LWE part (one copy): public U, V and, unless
// PUBLIC_ONLY, the message bits and the randomness.
template <class Field, class LP>
void fill_lwe(PackedLayer<Field>& w, const Field& f,
              const LweCiphertext<LP>& ct,
              const std::array<uint8_t, kLweMsgBytes>* m,
              const LweRandomness<LP>* rnd) {
  size_t i = 0;
  w.set_bit(i++, 0, true);
  auto put = [&](uint32_t x) {
    const auto e = f.of_scalar(x);
    w.set_wire(i++, &e);
  };
  for (const Poly& p : ct.u) for (uint32_t x : p) put(x);
  for (const Poly& p : ct.v) for (uint32_t x : p) put(x);
  if (m == nullptr) return;
  for (size_t b = 0; b < 8 * kLweMsgBytes; ++b) {
    w.set_bit(i++, 0, ((*m)[b / 8] >> (b % 8)) & 1);
  }
  for (const Poly& p : rnd->r) for (uint32_t x : p) put(x);
  for (const Poly& p : rnd->e1) for (uint32_t x : p) put(x);
  for (const Poly& p : rnd->e2) for (uint32_t x : p) put(x);
}

}  // namespace pq_cred
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_CREDENTIAL_LWE_H_
