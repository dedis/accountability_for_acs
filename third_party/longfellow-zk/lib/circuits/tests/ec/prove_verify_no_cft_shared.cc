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

#include "circuits/tests/ec/prove_verify_no_cft_shared.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <type_traits>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/crypto.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"

namespace proofs {

template <typename Traits>
struct BenchmarkContext;

template <typename Traits>
std::unique_ptr<Circuit<typename Traits::Field>> make_circuit(size_t numInstances);

template <typename Traits>
void fill_input(Dense<typename Traits::Field>& W, const BenchmarkContext<Traits>& ctx,
                bool prover);

// Keep the string storage in this TU (header declares extern).
const char kP256ExtRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
const char kP256ExtRootY[] =
    "840879943585409076957404614278186605601821689971823787493130182544504602"
    "12908";

const P256Traits::EC& P256Traits::ec() { return p256; }
const P256Traits::Field& P256Traits::field() { return p256_base; }
const P256Traits::Scalar& P256Traits::scalar_field() { return p256_scalar; }

template <class Field>
static void to_bytes_be(const Field& f, const typename Field::Elt& x,
                        uint8_t out[32]) {
  uint8_t tmp[32];
  f.to_bytes_field(tmp, x);
  for (size_t i = 0; i < 32; ++i) out[i] = tmp[31 - i];
}

template <class Field>
static typename Field::Elt sha_state_to_field(const Field& f,
                                              const uint32_t h1[8]) {
  uint8_t le[32];
  for (size_t i = 0; i < 8; ++i) {
    const uint32_t w = h1[7 - i];
    le[4 * i + 0] = static_cast<uint8_t>(w & 0xff);
    le[4 * i + 1] = static_cast<uint8_t>((w >> 8) & 0xff);
    le[4 * i + 2] = static_cast<uint8_t>((w >> 16) & 0xff);
    le[4 * i + 3] = static_cast<uint8_t>((w >> 24) & 0xff);
  }
  return f.of_bytes_field(le).value();
}

struct OpenSslKeyPair {
  EC_KEY* key = nullptr;
  EC_GROUP* group = nullptr;

  OpenSslKeyPair()
      : key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)),
        group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) {
    check(key != nullptr, "EC_KEY_new_by_curve_name failed");
    check(group != nullptr, "EC_GROUP_new_by_curve_name failed");
  }

  ~OpenSslKeyPair() {
    EC_KEY_free(key);
    EC_GROUP_free(group);
  }

  OpenSslKeyPair(const OpenSslKeyPair&) = delete;
  OpenSslKeyPair& operator=(const OpenSslKeyPair&) = delete;
};

static std::array<uint8_t, 32> bn_to_bytes32_be(const BIGNUM* bn) {
  std::array<uint8_t, 32> out{};
  int ret = BN_bn2binpad(bn, out.data(), static_cast<int>(out.size()));
  check(ret == static_cast<int>(out.size()), "BN_bn2binpad failed");
  return out;
}

static void sign_digest_be32(const EC_KEY* key, const uint8_t digest_be[32],
                             std::array<uint8_t, 32>& r_be,
                             std::array<uint8_t, 32>& s_be) {
  ECDSA_SIG* sig = ECDSA_do_sign(digest_be, 32, const_cast<EC_KEY*>(key));
  check(sig != nullptr, "ECDSA_do_sign failed");
  r_be = bn_to_bytes32_be(ECDSA_SIG_get0_r(sig));
  s_be = bn_to_bytes32_be(ECDSA_SIG_get0_s(sig));
  ECDSA_SIG_free(sig);
}

static void extract_pubkey_bytes(const EC_KEY* key, const EC_GROUP* group,
                                 std::array<uint8_t, 32>& x,
                                 std::array<uint8_t, 32>& y) {
  const EC_POINT* pub = EC_KEY_get0_public_key(key);
  check(pub != nullptr, "missing EC public key");
  uint8_t buf[65];
  size_t len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, buf,
                                  sizeof(buf), nullptr);
  check(len == sizeof(buf), "EC_POINT_point2oct failed");
  std::memcpy(x.data(), buf + 1, 32);
  std::memcpy(y.data(), buf + 33, 32);
}

template <class LogicCircuit, class Field, class EC>
class CredentialCommitmentProveVerifyNoCftCircuit {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Nat = typename Field::N;
  using Ecdsa = VerifyCircuit<LogicCircuit, Field, EC>;
  static constexpr size_t kShaPluckerBits = 3;

  using Flatsha =
      FlatSHA256Circuit<LogicCircuit, BitPlucker<LogicCircuit, kShaPluckerBits>>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;

  static constexpr size_t kNumAttrs = kProveVerifyNoCftCredentialAttrs;
  static constexpr size_t kCredentialShaBlocks = kProveVerifyNoCftCredentialShaBlocks;
  static constexpr size_t kDigestBytes = 32;

 public:
  struct CredentialShaWitness {
    v8 nb;
    v8 sha_in[64 * kProveVerifyNoCftCredentialShaBlocks];
    ShaBlockWitness sha_bw[kProveVerifyNoCftCredentialShaBlocks];
    void input(const LogicCircuit& lc) {
      nb = lc.template vinput<8>();
      for (size_t i = 0; i < 64 * kProveVerifyNoCftCredentialShaBlocks; ++i) {
        sha_in[i] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < kProveVerifyNoCftCredentialShaBlocks; ++j) {
        sha_bw[j].input(lc);
      }
    }
  };

  struct Witness {
    typename Ecdsa::Witness issuer_sig;
    typename Ecdsa::Witness hw_sig;

    EltW hw_pk_x;
    EltW hw_pk_y;

    EltW birth_bits[kProveVerifyNoCftTsBits];
    EltW valid_from_bits[kProveVerifyNoCftTsBits];
    EltW valid_until_bits[kProveVerifyNoCftTsBits];
    EltW now_bits[kProveVerifyNoCftTsBits];
    EltW max_birth_bits[kProveVerifyNoCftTsBits];

    v8 attr_bytes[kNumAttrs][kDigestBytes];
    CredentialShaWitness credential_sha;
    v256 credential_digest_bits;

    void input(const LogicCircuit& lc) {
      issuer_sig.input(lc);
      hw_sig.input(lc);

      hw_pk_x = lc.eltw_input();
      hw_pk_y = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) birth_bits[i] = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) valid_from_bits[i] = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) valid_until_bits[i] = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) now_bits[i] = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) max_birth_bits[i] = lc.eltw_input();

      for (size_t a = 0; a < kNumAttrs; ++a) {
        for (size_t i = 0; i < kDigestBytes; ++i) {
          attr_bytes[a][i] = lc.template vinput<8>();
        }
      }
      credential_sha.input(lc);
      credential_digest_bits = lc.template vinput<256>();
    }
  };

  CredentialCommitmentProveVerifyNoCftCircuit(const LogicCircuit& lc, const EC& ec,
                                         const Nat& order)
      : lc_(lc), ec_(ec), order_(order) {}

  void prove_relation(EltW issuer_x, EltW issuer_y, EltW m_pub, EltW now_pub,
                      EltW max_birth_pub, const Witness& w) const {
    Flatsha sha(lc_);

    auto repack_be32_from_bytes = [&](const v8 be[32]) -> EltW {
      EltW h = lc_.konst(0);
      EltW base = lc_.konst(2);
      for (size_t i = 0; i < 32; ++i) {
        for (size_t j = 0; j < 8; ++j) {
          auto t = lc_.mul(h, base);
          auto bit = lc_.eval(be[i][7 - j]);
          h = lc_.add(bit, t);
        }
      }
      return h;
    };

    auto bits_to_elt = [&](const EltW bits[kProveVerifyNoCftTsBits]) -> EltW {
      EltW acc = lc_.konst(0);
      EltW twok = lc_.konst(1);
      for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) {
        BitW bi(bits[i], lc_.f_);
        lc_.assert_is_bit(bi);
        acc = lc_.add(acc, lc_.mul(bits[i], twok));
        twok = lc_.add(twok, twok);
      }
      return acc;
    };

    EltW birth_val = bits_to_elt(w.birth_bits);
    EltW valid_from_val = bits_to_elt(w.valid_from_bits);
    EltW valid_until_val = bits_to_elt(w.valid_until_bits);
    EltW now_val = bits_to_elt(w.now_bits);
    EltW max_birth_val = bits_to_elt(w.max_birth_bits);

    lc_.assert_eq(now_val, now_pub);
    lc_.assert_eq(max_birth_val, max_birth_pub);

    // Flat SHA-256 over 32 Merkle-style leaf digests (each SHA256(be32(i)||attr_i)).
    sha.assert_message_hash(kProveVerifyNoCftCredentialShaBlocks, w.credential_sha.nb,
                            w.credential_sha.sha_in, w.credential_digest_bits,
                            w.credential_sha.sha_bw);
    EltW digest_field = repack32(
        sha, w.credential_sha.sha_bw[kProveVerifyNoCftCredentialShaBlocks - 1].h1);

    // Bind only the non-CFT attributes to their slots.
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[4]), birth_val);
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[5]), valid_from_val);
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[6]), valid_until_val);
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[14]), w.hw_pk_x);
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[15]), w.hw_pk_y);

    auto mk_bitw = [&](const EltW bits_lsb[kProveVerifyNoCftTsBits],
                       BitW out[kProveVerifyNoCftTsBits]) {
      for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) {
        out[i] = BitW(bits_lsb[kProveVerifyNoCftTsBits - 1 - i], lc_.f_);
      }
    };
    BitW b_birth[kProveVerifyNoCftTsBits], b_vf[kProveVerifyNoCftTsBits],
        b_vu[kProveVerifyNoCftTsBits], b_now[kProveVerifyNoCftTsBits],
        b_max[kProveVerifyNoCftTsBits];
    mk_bitw(w.birth_bits, b_birth);
    mk_bitw(w.valid_from_bits, b_vf);
    mk_bitw(w.valid_until_bits, b_vu);
    mk_bitw(w.now_bits, b_now);
    mk_bitw(w.max_birth_bits, b_max);

    lc_.assert1(lc_.leq(kProveVerifyNoCftTsBits, b_birth, b_max));
    lc_.assert1(lc_.leq(kProveVerifyNoCftTsBits, b_vf, b_now));
    lc_.assert1(lc_.leq(kProveVerifyNoCftTsBits, b_now, b_vu));

    Ecdsa issuer_verifier(lc_, ec_, order_);
    issuer_verifier.verify_signature3(issuer_x, issuer_y, digest_field,
                                      w.issuer_sig);

    Ecdsa hw_verifier(lc_, ec_, order_);
    hw_verifier.verify_signature3(w.hw_pk_x, w.hw_pk_y, m_pub, w.hw_sig);
  }

 private:
  EltW repack32(const Flatsha& sha,
                const typename Flatsha::packed_v32 H[8]) const {
    EltW h = lc_.konst(0);
    auto twok = lc_.one();
    for (size_t j = 8; j-- > 0;) {
      auto hj = sha.bp_.unpack_v32(H[j]);
      for (size_t k = 0; k < 32; ++k) {
        h = lc_.axpy(h, twok, lc_.eval(hj[k]));
        lc_.f_.add(twok, twok);
      }
    }
    return h;
  }

  const LogicCircuit& lc_;
  const EC& ec_;
  const Nat& order_;
};

template <typename Traits>
struct BenchmarkContext {
  using Field = typename Traits::Field;
  using EC = typename Traits::EC;
  using Nat = typename Field::N;
  using Field2 = Fp2<Fp256Base>;
  using Elt2 = typename Field2::Elt;
  using ConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, Field2>;
  using RSFactory = ReedSolomonFactory<Fp256Base, ConvolutionFactory>;
  using EcdsaWitness = VerifyWitness3<EC, typename Traits::Scalar>;

  static_assert(std::is_same_v<Field, Fp256Base>,
                "FFT-ext backend currently only supported for Fp256Base");

  std::unique_ptr<Circuit<Field>> circuit;
  Dense<Field> w;
  Field2 field2;
  Elt2 omega;
  ConvolutionFactory factory;
  RSFactory rsf;
  Transcript tp;
  SecureRandomEngine rng;
  std::unique_ptr<ZkProof<Field>> zkpr;
  ZkProver<Field, RSFactory> prover;

  typename Field::Elt dummy_pub;
  typename Field::Elt issuer_pub_x;
  typename Field::Elt issuer_pub_y;
  typename Field::Elt m_pub;
  typename Field::Elt now_pub;
  typename Field::Elt max_birth_pub;

  std::array<std::array<uint8_t, 32>, kProveVerifyNoCftCredentialAttrs> attr_values{};
  std::array<uint8_t, 32> credential_digest_be{};
  std::array<uint8_t, 64 * kProveVerifyNoCftCredentialShaBlocks> credential_sha_in{};
  std::array<FlatSHA256Witness::BlockWitness, kProveVerifyNoCftCredentialShaBlocks>
      credential_sha_bw{};

  typename Field::Elt hw_pk_x;
  typename Field::Elt hw_pk_y;

  std::array<typename Field::Elt, kProveVerifyNoCftTsBits> birth_bits{};
  std::array<typename Field::Elt, kProveVerifyNoCftTsBits> valid_from_bits{};
  std::array<typename Field::Elt, kProveVerifyNoCftTsBits> valid_until_bits{};
  std::array<typename Field::Elt, kProveVerifyNoCftTsBits> now_bits{};
  std::array<typename Field::Elt, kProveVerifyNoCftTsBits> max_birth_bits{};

  EcdsaWitness issuer_sig;
  EcdsaWitness hw_sig;

  OpenSslKeyPair issuer_key;
  OpenSslKeyPair hw_key;

  size_t show_counter_{0};
  bool credential_initialized_{false};

  explicit BenchmarkContext(size_t numInstances)
      : circuit(make_circuit<Traits>(numInstances)),
        w(1, circuit->ninputs),
        field2(Traits::field()),
        omega(field2.of_string(kP256ExtRootX, kP256ExtRootY)),
        factory(Traits::field(), field2, omega, kP256ExtRootOrder),
        rsf(factory, Traits::field()),
        tp((uint8_t*)"benchmark", 9),
        zkpr(std::make_unique<ZkProof<Field>>(*circuit, kProveVerifyNoCftRate,
                                              kProveVerifyNoCftQueries)),
        prover(*circuit, Traits::field(), rsf),
        issuer_sig(Traits::scalar_field(), Traits::ec()),
        hw_sig(Traits::scalar_field(), Traits::ec()) {
    set_log_level(ERROR);
    init_credential_once();
  }

  void init_credential_once() {
    if (credential_initialized_) return;
    const auto& field = Traits::field();

    check(EC_KEY_generate_key(issuer_key.key) == 1, "issuer keygen failed");
    check(EC_KEY_generate_key(hw_key.key) == 1, "hw keygen failed");
    std::array<uint8_t, 32> issuer_px_bytes{};
    std::array<uint8_t, 32> issuer_py_bytes{};
    extract_pubkey_bytes(issuer_key.key, issuer_key.group, issuer_px_bytes,
                         issuer_py_bytes);

    auto field_from_be32 = [&](const uint8_t be[32]) -> typename Field::Elt {
      uint8_t le[32];
      for (size_t i = 0; i < 32; ++i) le[i] = be[31 - i];
      return field.of_bytes_field(le).value();
    };
    issuer_pub_x = field_from_be32(issuer_px_bytes.data());
    issuer_pub_y = field_from_be32(issuer_py_bytes.data());
    dummy_pub = field.zero();

    std::array<uint8_t, 32> hw_px_bytes{};
    std::array<uint8_t, 32> hw_py_bytes{};
    extract_pubkey_bytes(hw_key.key, hw_key.group, hw_px_bytes, hw_py_bytes);
    hw_pk_x = field_from_be32(hw_px_bytes.data());
    hw_pk_y = field_from_be32(hw_py_bytes.data());

    const Nat m_nat = Nat(42424242);
    m_pub = field.to_montgomery(m_nat);

    const uint64_t one_day_ms = 24ULL * 60ULL * 60ULL * 1000ULL;
    const uint64_t eighteen_years_ms = (18ULL * 36525ULL * one_day_ms) / 100ULL;
    const uint64_t base_now_ms = 1710000000000ULL;
    const uint64_t max_birth_ms = base_now_ms - eighteen_years_ms;
    const uint64_t birth_ms = max_birth_ms - 365ULL * one_day_ms;
    const uint64_t valid_from_ms = base_now_ms - one_day_ms;
    const uint64_t valid_until_ms = base_now_ms + 365ULL * one_day_ms;

    Nat max_birth_nat(max_birth_ms);
    Nat birth_nat(birth_ms);
    Nat valid_from_nat(valid_from_ms);
    Nat valid_until_nat(valid_until_ms);

    max_birth_pub = field.to_montgomery(max_birth_nat);

    std::array<uint8_t, kProveVerifyNoCftCredentialMsgBytes> attr_msg{};
    {
      uint8_t buf[32];
      to_bytes_be(field, field.to_montgomery(birth_nat), buf);
      std::memcpy(&attr_msg[4 * 32], buf, 32);
      to_bytes_be(field, field.to_montgomery(valid_from_nat), buf);
      std::memcpy(&attr_msg[5 * 32], buf, 32);
      to_bytes_be(field, field.to_montgomery(valid_until_nat), buf);
      std::memcpy(&attr_msg[6 * 32], buf, 32);
      to_bytes_be(field, hw_pk_x, buf);
      std::memcpy(&attr_msg[14 * 32], buf, 32);
      to_bytes_be(field, hw_pk_y, buf);
      std::memcpy(&attr_msg[15 * 32], buf, 32);
    }
    for (size_t i = 0; i < kProveVerifyNoCftCredentialAttrs; ++i) {
      std::memcpy(attr_values[i].data(), &attr_msg[i * 32], 32);
    }

    auto sha256_64_digest = [](const uint8_t msg64[64], uint8_t out[32]) {
      SHA256 sha;
      sha.Update(msg64, 64);
      sha.DigestData(out);
    };
    auto be32_index = [](uint8_t out[32], uint8_t idx) {
      std::memset(out, 0, 32);
      out[31] = idx;
    };
    std::array<uint8_t, kProveVerifyNoCftCredentialMsgBytes> leaf_msg{};
    for (size_t i = 0; i < kProveVerifyNoCftCredentialAttrs; ++i) {
      uint8_t name_be[32];
      be32_index(name_be, static_cast<uint8_t>(i));
      uint8_t msg64[64];
      std::memcpy(msg64, name_be, 32);
      std::memcpy(msg64 + 32, attr_values[i].data(), 32);
      sha256_64_digest(msg64, &leaf_msg[i * 32]);
    }

    uint8_t cred_nb = 0;
    FlatSHA256Witness::transform_and_witness_message(
        kProveVerifyNoCftCredentialMsgBytes, leaf_msg.data(),
        kProveVerifyNoCftCredentialShaBlocks, cred_nb, credential_sha_in.data(),
        credential_sha_bw.data());

    {
      const auto& last_h = credential_sha_bw[kProveVerifyNoCftCredentialShaBlocks - 1];
      for (size_t j = 0; j < 8; ++j) {
        const uint32_t w = last_h.h1[j];
        credential_digest_be[4 * j + 0] = static_cast<uint8_t>(w >> 24);
        credential_digest_be[4 * j + 1] = static_cast<uint8_t>(w >> 16);
        credential_digest_be[4 * j + 2] = static_cast<uint8_t>(w >> 8);
        credential_digest_be[4 * j + 3] = static_cast<uint8_t>(w);
      }
    }

    auto fill_bits_from_u64 =
        [&](std::array<typename Field::Elt, kProveVerifyNoCftTsBits>& out, uint64_t x) {
          Nat n(x);
          for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i)
            out[i] = field.of_scalar(n.bit(i));
        };
    fill_bits_from_u64(birth_bits, birth_ms);
    fill_bits_from_u64(valid_from_bits, valid_from_ms);
    fill_bits_from_u64(valid_until_bits, valid_until_ms);
    fill_bits_from_u64(max_birth_bits, max_birth_ms);

    {
      const typename Field::Elt digest_pub =
          sha_state_to_field(field, credential_sha_bw[kProveVerifyNoCftCredentialShaBlocks - 1].h1);
      uint8_t e_be[32];
      to_bytes_be(field, digest_pub, e_be);

      auto nat_from_be32 = [](const uint8_t be[32]) -> Nat {
        uint8_t le[32];
        for (size_t i = 0; i < 32; ++i) le[i] = be[31 - i];
        return Nat::of_bytes(le);
      };
      const Nat e_nat = nat_from_be32(e_be);

      std::array<uint8_t, 32> r_be{}, s_be{};
      sign_digest_be32(issuer_key.key, e_be, r_be, s_be);

      Nat r_nat = nat_from_be32(r_be.data());
      Nat s_nat = nat_from_be32(s_be.data());

      check(issuer_sig.compute_witness(issuer_pub_x, issuer_pub_y, e_nat, r_nat,
                                       s_nat),
            "issuer witness generation failed");
    }

    {
      const Nat m_nat2 = field.from_montgomery(m_pub);
      uint8_t m_le[Nat::kBytes];
      m_nat2.to_bytes(m_le);
      uint8_t m_be[32];
      for (size_t i = 0; i < 32; ++i) m_be[i] = m_le[31 - i];

      std::array<uint8_t, 32> r_be{}, s_be{};
      sign_digest_be32(hw_key.key, m_be, r_be, s_be);

      auto nat_from_be32 = [](const uint8_t be[32]) -> Nat {
        uint8_t le[32];
        for (size_t i = 0; i < 32; ++i) le[i] = be[31 - i];
        return Nat::of_bytes(le);
      };
      Nat r_nat = nat_from_be32(r_be.data());
      Nat s_nat = nat_from_be32(s_be.data());

      check(hw_sig.compute_witness(hw_pk_x, hw_pk_y, m_nat2, r_nat, s_nat),
            "hardware witness generation failed");
    }

    credential_initialized_ = true;
  }

  void refresh_show_inputs() {
    check(credential_initialized_, "init_credential_once() required before refresh_show_inputs()");
    ++show_counter_;
    const auto& field = Traits::field();

    const uint64_t base_now_ms = 1710000000000ULL;
    const uint64_t now_ms = base_now_ms + show_counter_;
    Nat now_nat(now_ms);
    now_pub = field.to_montgomery(now_nat);

    Nat n(now_ms);
    for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) {
      now_bits[i] = field.of_scalar(n.bit(i));
    }
    (void)field;
  }

  void build_inputs() {
    init_credential_once();
    refresh_show_inputs();
  }
};

template <typename Traits>
std::unique_ptr<Circuit<typename Traits::Field>> make_circuit(size_t numInstances) {
  using Field = typename Traits::Field;
  using EC = typename Traits::EC;
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltW = typename LogicCircuit::EltW;
  using CircuitT = CredentialCommitmentProveVerifyNoCftCircuit<LogicCircuit, Field, EC>;

  QuadCircuit<Field> Q(Traits::field());
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, Traits::field());
  CircuitT circuit(lc, Traits::ec(), n256_order);

  std::vector<EltW> issuer_x(numInstances), issuer_y(numInstances);
  std::vector<EltW> m(numInstances);
  std::vector<EltW> now(numInstances), max_birth(numInstances);
  for (size_t i = 0; i < numInstances; ++i) {
    issuer_x[i] = lc.eltw_input();
    issuer_y[i] = lc.eltw_input();
    m[i] = lc.eltw_input();
    now[i] = lc.eltw_input();
    max_birth[i] = lc.eltw_input();
  }

  Q.private_input();
  std::vector<typename CircuitT::Witness> ws(numInstances);
  for (size_t i = 0; i < numInstances; ++i) {
    ws[i].input(lc);
  }
  for (size_t i = 0; i < numInstances; ++i) {
    circuit.prove_relation(issuer_x[i], issuer_y[i], m[i], now[i], max_birth[i], ws[i]);
  }

  auto compiled = Q.mkcircuit(1);

  static std::once_flag dump_once;
  std::call_once(dump_once, [&]() {
    dump_info("prove_verify_no_cft", numInstances, Q);
  });
  return compiled;
}

template <typename Traits>
void fill_input(Dense<typename Traits::Field>& W, const BenchmarkContext<Traits>& ctx,
                bool prover) {
  using EC = typename Traits::EC;
  using Field = typename Traits::Field;
  DenseFiller<Field> filler(W);

  filler.push_back(ctx.dummy_pub);
  filler.push_back(ctx.issuer_pub_x);
  filler.push_back(ctx.issuer_pub_y);
  filler.push_back(ctx.m_pub);
  filler.push_back(ctx.now_pub);
  filler.push_back(ctx.max_birth_pub);

  if (!prover) return;

  BitPluckerEncoder<Field, 3> enc(Traits::field());

  auto push_sig = [&](const auto& src) {
    filler.push_back(src.rx_);
    filler.push_back(src.ry_);
    filler.push_back(src.rx_inv_);
    filler.push_back(src.s_inv_);
    filler.push_back(src.pk_inv_);
    for (size_t i = 0; i < 8; ++i) filler.push_back(src.pre_[i]);
    for (size_t i = 0; i < EC::kBits; ++i) {
      filler.push_back(src.bi_[i]);
      if (i < EC::kBits - 1) {
        filler.push_back(src.int_x_[i]);
        filler.push_back(src.int_y_[i]);
        filler.push_back(src.int_z_[i]);
      }
    }
  };
  push_sig(ctx.issuer_sig);
  push_sig(ctx.hw_sig);

  filler.push_back(ctx.hw_pk_x);
  filler.push_back(ctx.hw_pk_y);
  for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) filler.push_back(ctx.birth_bits[i]);
  for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) filler.push_back(ctx.valid_from_bits[i]);
  for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) filler.push_back(ctx.valid_until_bits[i]);
  for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) filler.push_back(ctx.now_bits[i]);
  for (size_t i = 0; i < kProveVerifyNoCftTsBits; ++i) filler.push_back(ctx.max_birth_bits[i]);

  for (size_t a = 0; a < kProveVerifyNoCftCredentialAttrs; ++a) {
    for (size_t i = 0; i < 32; ++i) {
      filler.push_back(ctx.attr_values[a][i], 8, Traits::field());
    }
  }

  filler.push_back(static_cast<uint8_t>(kProveVerifyNoCftCredentialShaBlocks), 8, Traits::field());
  for (size_t i = 0; i < 64 * kProveVerifyNoCftCredentialShaBlocks; ++i) {
    filler.push_back(ctx.credential_sha_in[i], 8, Traits::field());
  }
  for (size_t b = 0; b < kProveVerifyNoCftCredentialShaBlocks; ++b) {
    for (size_t k = 0; k < 48; ++k) {
      filler.push_back(enc.mkpacked_v32(ctx.credential_sha_bw[b].outw[k]));
    }
    for (size_t k = 0; k < 64; ++k) {
      filler.push_back(enc.mkpacked_v32(ctx.credential_sha_bw[b].oute[k]));
      filler.push_back(enc.mkpacked_v32(ctx.credential_sha_bw[b].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) {
      filler.push_back(enc.mkpacked_v32(ctx.credential_sha_bw[b].h1[k]));
    }
  }

  for (size_t j = 0; j < 256; ++j) {
    const uint8_t byte = ctx.credential_digest_be[(255 - j) / 8];
    const uint8_t bit = (byte >> (j % 8)) & 1;
    filler.push_back(bit ? Traits::field().one() : Traits::field().zero());
  }

  if (filler.size() != W.n1_) {
    log(ERROR, "fill_input size mismatch: filled=%zu expected=%zu", filler.size(),
        W.n1_);
    check(false, "fill_input size mismatch");
  }
}

class CredentialCommitmentProveVerifyNoCftHarnessP256 {
 public:
  explicit CredentialCommitmentProveVerifyNoCftHarnessP256(size_t numInstances)
      : ctx_(numInstances),
        verifier_(*ctx_.circuit, ctx_.rsf, kProveVerifyNoCftRate, kProveVerifyNoCftQueries,
                  P256Traits::field()) {}

  void RebuildCredential() { ctx_.refresh_show_inputs(); }

  bool Prove() {
    fill_input<P256Traits>(ctx_.w, ctx_, /*prover=*/true);

    ctx_.zkpr = std::make_unique<ZkProof<Fp256Base>>(*ctx_.circuit, kProveVerifyNoCftRate,
                                                     kProveVerifyNoCftQueries);
    Transcript tp((uint8_t*)"benchmark", 9);
    ctx_.prover.commit(*ctx_.zkpr, ctx_.w, tp, ctx_.rng);
    return ctx_.prover.prove(*ctx_.zkpr, ctx_.w, tp);
  }

  void fill_public_inputs(Dense<Fp256Base>& pub) const {
    fill_input<P256Traits>(pub, ctx_, /*prover=*/false);
  }

  bool Verify(const Dense<Fp256Base>& pub) const {
    Transcript tv((uint8_t*)"benchmark", 9);
    verifier_.recv_commitment(*ctx_.zkpr, tv);
    return verifier_.verify(*ctx_.zkpr, pub, tv);
  }

 private:
  BenchmarkContext<P256Traits> ctx_;
  ZkVerifier<Fp256Base, typename BenchmarkContext<P256Traits>::RSFactory> verifier_;
};

void CredentialCommitmentProveVerifyNoCftHarnessP256Deleter::operator()(
    CredentialCommitmentProveVerifyNoCftHarnessP256* p) const {
  delete p;
}

CredentialCommitmentProveVerifyNoCftHarnessP256Ptr MakeCredentialCommitmentProveVerifyNoCftHarnessP256(
    size_t numInstances) {
  return CredentialCommitmentProveVerifyNoCftHarnessP256Ptr(
      new CredentialCommitmentProveVerifyNoCftHarnessP256(numInstances));
}

bool ProveVerifyNoCftP256(CredentialCommitmentProveVerifyNoCftHarnessP256& h) {
  return h.Prove();
}

void RebuildBenchmarkCredentialNoCftP256(CredentialCommitmentProveVerifyNoCftHarnessP256& h) {
  h.RebuildCredential();
}

std::unique_ptr<Dense<Fp256Base>> PublicInputsProveVerifyNoCftP256(
    const CredentialCommitmentProveVerifyNoCftHarnessP256& h) {
  auto pub = std::make_unique<Dense<Fp256Base>>(1, /*n1=*/6);
  h.fill_public_inputs(*pub);
  return pub;
}

bool VerifyProveVerifyNoCftP256(const CredentialCommitmentProveVerifyNoCftHarnessP256& h,
                           const Dense<Fp256Base>& pub) {
  return h.Verify(pub);
}

}  // namespace proofs

