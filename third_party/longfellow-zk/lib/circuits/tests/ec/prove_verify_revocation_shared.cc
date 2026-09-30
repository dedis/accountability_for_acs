// Copyright 2026 Google LLC.
//
// ProveVerify + CFT + packed status-list revocation (SHA-256 Merkle).

#include "circuits/tests/ec/prove_verify_revocation_shared.h"

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
namespace {

constexpr uint64_t kP256ExtRootOrder = 1ull << 31;

const char kP256ExtRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
const char kP256ExtRootY[] =
    "840879943585409076957404614278186605601821689971823787493130182544504602"
    "12908";

struct P256Traits {
  using Field = Fp256Base;
  using Scalar = Fp256Scalar;
  using EC = P256;

  static const EC& ec();
  static const Field& field();
  static const Scalar& scalar_field();
};

const P256Traits::EC& P256Traits::ec() { return p256; }
const P256Traits::Field& P256Traits::field() { return p256_base; }
const P256Traits::Scalar& P256Traits::scalar_field() { return p256_scalar; }

constexpr size_t kShaPluckerBits = 3;
constexpr size_t kShaBlocks64 = 2;

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

template <class EC>
struct ScalarMulWitnessNative {
  using Field = typename EC::Field;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  static constexpr size_t kBits = EC::kBits;

  Elt bits[kBits];
  Elt int_x[kBits];
  Elt int_y[kBits];
  Elt int_z[kBits];
  const EC& ec;

  explicit ScalarMulWitnessNative(const EC& ec) : ec(ec) {}

  void compute(const Nat& scalar, const Elt& base_x, const Elt& base_y) {
    const Field& f = ec.f_;
    const Elt one = f.one();
    Elt ax = f.zero();
    Elt ay = one;
    Elt az = f.zero();
    for (size_t i = 0; i < kBits; ++i) {
      const size_t bit_idx = kBits - 1 - i;
      const int bit = scalar.bit(bit_idx);
      bits[i] = f.of_scalar(bit);
      ec.doubleE(ax, ay, az, ax, ay, az);
      if (bit == 1) {
        ec.addE(ax, ay, az, ax, ay, az, base_x, base_y, one);
      } else {
        ec.addE(ax, ay, az, ax, ay, az, f.zero(), one, f.zero());
      }
      int_x[i] = ax;
      int_y[i] = ay;
      int_z[i] = az;
    }
  }
};

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

static void sha256_witness_64(const uint8_t msg64[64],
                              std::array<FlatSHA256Witness::BlockWitness, 2>& out) {
  std::array<uint8_t, 128> tmp{};
  uint8_t numb = 0;
  FlatSHA256Witness::transform_and_witness_message(64, msg64, 2, numb, tmp.data(),
                                                   out.data());
  check(numb == 2, "sha64 witness blocks mismatch");
}

static std::array<uint8_t, 32> digest_bytes_from_bw(
    const std::array<FlatSHA256Witness::BlockWitness, 2>& bw) {
  std::array<uint8_t, 32> out{};
  for (size_t j = 0; j < 8; ++j) {
    const uint32_t w = bw[1].h1[j];
    const size_t base = j * 4;
    out[base + 0] = static_cast<uint8_t>(w >> 24);
    out[base + 1] = static_cast<uint8_t>(w >> 16);
    out[base + 2] = static_cast<uint8_t>(w >> 8);
    out[base + 3] = static_cast<uint8_t>(w);
  }
  return out;
}

static void push_sha64_bw(DenseFiller<Fp256Base>& f,
                          const std::array<FlatSHA256Witness::BlockWitness, 2>& bw) {
  BitPluckerEncoder<Fp256Base, kShaPluckerBits> enc(p256_base);
  for (size_t b = 0; b < 2; ++b) {
    for (size_t k = 0; k < 48; ++k) f.push_back(enc.mkpacked_v32(bw[b].outw[k]));
    for (size_t k = 0; k < 64; ++k) {
      f.push_back(enc.mkpacked_v32(bw[b].oute[k]));
      f.push_back(enc.mkpacked_v32(bw[b].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) f.push_back(enc.mkpacked_v32(bw[b].h1[k]));
  }
}

static void zero_digest(std::array<uint8_t, 32>& d) { d.fill(0); }

static std::array<uint8_t, 32> hash2_be(const std::array<uint8_t, 32>& L,
                                        const std::array<uint8_t, 32>& R) {
  uint8_t msg64[64];
  std::memcpy(msg64, L.data(), 32);
  std::memcpy(msg64 + 32, R.data(), 32);
  std::array<uint8_t, 32> out{};
  SHA256 sha;
  sha.Update(msg64, 64);
  sha.DigestData(out.data());
  return out;
}

static std::array<std::array<uint8_t, 32>, 64> build_uniform_zero_level_hashes(
    size_t depth) {
  check(depth < 64, "depth too large");
  std::array<std::array<uint8_t, 32>, 64> level{};
  zero_digest(level[0]);
  for (size_t i = 0; i < depth; ++i) {
    level[i + 1] = hash2_be(level[i], level[i]);
  }
  return level;
}

struct PathWitness {
  std::array<std::array<uint8_t, 32>, 32> path_elements{};
  std::array<Fp256Base::Elt, 32> path_indices{};
  std::array<std::array<FlatSHA256Witness::BlockWitness, 2>, 32> node_bw{};
  size_t depth = 0;
};

static void fill_path_for_uniform_zero_tree(size_t depth, size_t leaf_index,
                                            const std::array<std::array<uint8_t, 32>, 64>& levels,
                                            PathWitness& out) {
  out.depth = depth;
  for (size_t d = 0; d < depth; ++d) {
    const bool is_right = ((leaf_index >> d) & 1) != 0;
    out.path_indices[d] = is_right ? p256_base.one() : p256_base.zero();
    out.path_elements[d] = levels[d];

    uint8_t msg64[64];
    std::memcpy(msg64, levels[d].data(), 32);
    std::memcpy(msg64 + 32, levels[d].data(), 32);
    sha256_witness_64(msg64, out.node_bw[d]);
    const auto got = digest_bytes_from_bw(out.node_bw[d]);
    check(got == levels[d + 1], "uniform zero path bw mismatch");
  }
}

template <size_t Depth, class LogicCircuit, class Field, class EC>
class ProveVerifyRevocationCircuit {
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Nat = typename Field::N;
  using Ecdsa = VerifyCircuit<LogicCircuit, Field, EC>;
  static constexpr size_t kBits = EC::kBits;

  using Flatsha =
      FlatSHA256Circuit<LogicCircuit, BitPlucker<LogicCircuit, kShaPluckerBits>>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;

  static constexpr size_t kNumAttrs = kProveVerifyRevocCredentialAttrs;
  static constexpr size_t kDigestBytes = 32;

 public:
  struct ScalarBits {
    EltW bits[kBits];
    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kBits; ++i) bits[i] = lc.eltw_input();
    }
  };

  struct ScalarMulTrace {
    EltW int_x[kBits - 1];
    EltW int_y[kBits - 1];
    EltW int_z[kBits - 1];
    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kBits - 1; ++i) {
        int_x[i] = lc.eltw_input();
        int_y[i] = lc.eltw_input();
        int_z[i] = lc.eltw_input();
      }
    }
  };

  struct TagWitness {
    v8 sha_in[64 * kProveVerifyRevocTagShaBlocks];
    ShaBlockWitness sha_bw[kProveVerifyRevocTagShaBlocks];
    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < 64 * kProveVerifyRevocTagShaBlocks; ++i) {
        sha_in[i] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < kProveVerifyRevocTagShaBlocks; ++j) {
        sha_bw[j].input(lc);
      }
    }
  };

  struct CredentialShaWitness {
    v8 nb;
    v8 sha_in[64 * kProveVerifyRevocCredentialShaBlocks];
    ShaBlockWitness sha_bw[kProveVerifyRevocCredentialShaBlocks];
    void input(const LogicCircuit& lc) {
      nb = lc.template vinput<8>();
      for (size_t i = 0; i < 64 * kProveVerifyRevocCredentialShaBlocks; ++i) {
        sha_in[i] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < kProveVerifyRevocCredentialShaBlocks; ++j) {
        sha_bw[j].input(lc);
      }
    }
  };

  struct Witness {
    typename Ecdsa::Witness issuer_sig;
    typename Ecdsa::Witness c4_sig;

    EltW id_x;
    EltW id_y;
    EltW t;

    EltW birth_bits[kProveVerifyRevocTsBits];
    EltW valid_from_bits[kProveVerifyRevocTsBits];
    EltW valid_until_bits[kProveVerifyRevocTsBits];
    EltW now_bits[kProveVerifyRevocTsBits];
    EltW max_birth_bits[kProveVerifyRevocTsBits];

    v8 attr_bytes[kNumAttrs][kDigestBytes];
    CredentialShaWitness credential_sha;
    v256 credential_digest_bits;

    ScalarBits r1_bits;
    ScalarBits r2_bits;
    ScalarMulTrace r1G;
    ScalarMulTrace r2G;
    ScalarMulTrace r1Q;
    ScalarMulTrace r2Q;
    TagWitness tag;

    EltW credential_index;
    EltW leaf_index;
    EltW bit_index;
    v8 leaf_be[32];
    std::array<std::array<v8, 32>, Depth> path_sib;
    std::array<EltW, Depth> path_idx;
    std::array<std::array<ShaBlockWitness, 2>, Depth> node_bw;

    void input(const LogicCircuit& lc) {
      issuer_sig.input(lc);
      c4_sig.input(lc);

      id_x = lc.eltw_input();
      id_y = lc.eltw_input();
      t = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) birth_bits[i] = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) valid_from_bits[i] = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i)
        valid_until_bits[i] = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) now_bits[i] = lc.eltw_input();
      for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) max_birth_bits[i] = lc.eltw_input();

      for (size_t a = 0; a < kNumAttrs; ++a) {
        for (size_t i = 0; i < kDigestBytes; ++i) {
          attr_bytes[a][i] = lc.template vinput<8>();
        }
      }
      credential_sha.input(lc);
      credential_digest_bits = lc.template vinput<256>();

      r1_bits.input(lc);
      r2_bits.input(lc);
      r1G.input(lc);
      r2G.input(lc);
      r1Q.input(lc);
      r2Q.input(lc);
      tag.input(lc);

      credential_index = lc.eltw_input();
      leaf_index = lc.eltw_input();
      bit_index = lc.eltw_input();
      for (auto& b : leaf_be) b = lc.template vinput<8>();
      for (size_t d = 0; d < Depth; ++d) {
        for (auto& b : path_sib[d]) b = lc.template vinput<8>();
        path_idx[d] = lc.eltw_input();
      }
      for (size_t d = 0; d < Depth; ++d) {
        for (auto& w : node_bw[d]) w.input(lc);
      }
    }
  };

  ProveVerifyRevocationCircuit(const LogicCircuit& lc, const EC& ec, const Nat& order)
      : lc_(lc), ec_(ec), order_(order) {}

  void prove_relation(EltW issuer_x, EltW issuer_y, EltW elgamal_x, EltW elgamal_y,
                      EltW t_pub, EltW c1x_pub, EltW c1y_pub, EltW c2x_pub,
                      EltW c2y_pub, EltW c3x_pub, EltW c3y_pub, EltW c4_rx_pub,
                      EltW c4_ry_pub, EltW c4_s_pub, EltW now_pub, EltW max_birth_pub,
                      const std::array<v8, 32>& revocation_root_pub,
                      const Witness& w) const {
    EltW zero = lc_.konst(lc_.zero());
    EltW one = lc_.konst(lc_.one());
    EltW gx = lc_.konst(ec_.gx_);
    EltW gy = lc_.konst(ec_.gy_);

    auto scalar_mul_sliced = [&](EltW& outX, EltW& outY, EltW& outZ, EltW base_x,
                                 EltW base_y, const EltW bits[kBits],
                                 const ScalarMulTrace& tr) {
      EltW ax = zero, ay = one, az = zero;
      for (size_t i = 0; i < kBits; ++i) {
        BitW b_bit(bits[i], lc_.f_);
        lc_.assert_is_bit(b_bit);
        EltW tx = lc_.mux(b_bit, base_x, zero);
        EltW ty = lc_.mux(b_bit, base_y, one);
        EltW tz = lc_.mux(b_bit, one, zero);
        doubleE(ax, ay, az, ax, ay, az);
        addE(ax, ay, az, ax, ay, az, tx, ty, tz);
        if (i < kBits - 1) {
          lc_.assert_eq(ax, tr.int_x[i]);
          lc_.assert_eq(ay, tr.int_y[i]);
          lc_.assert_eq(az, tr.int_z[i]);
          ax = tr.int_x[i];
          ay = tr.int_y[i];
          az = tr.int_z[i];
        }
      }
      outX = ax;
      outY = ay;
      outZ = az;
    };

    auto assert_equal_projective = [&](EltW x1, EltW y1, EltW z1, EltW x2, EltW y2,
                                       EltW z2) {
      lc_.assert_eq(lc_.mul(x1, z2), lc_.mul(x2, z1));
      lc_.assert_eq(lc_.mul(y1, z2), lc_.mul(y2, z1));
    };

    EltW c1X, c1Y, c1Z;
    scalar_mul_sliced(c1X, c1Y, c1Z, gx, gy, w.r1_bits.bits, w.r1G);
    assert_equal_projective(c1X, c1Y, c1Z, c1x_pub, c1y_pub, one);

    EltW c2X, c2Y, c2Z;
    scalar_mul_sliced(c2X, c2Y, c2Z, gx, gy, w.r2_bits.bits, w.r2G);
    assert_equal_projective(c2X, c2Y, c2Z, c2x_pub, c2y_pub, one);

    EltW r1QX, r1QY, r1QZ;
    scalar_mul_sliced(r1QX, r1QY, r1QZ, elgamal_x, elgamal_y, w.r1_bits.bits,
                      w.r1Q);
    EltW c3X, c3Y, c3Z;
    addE(c3X, c3Y, c3Z, w.id_x, w.id_y, one, r1QX, r1QY, r1QZ);
    assert_equal_projective(c3X, c3Y, c3Z, c3x_pub, c3y_pub, one);

    EltW r2QX, r2QY, r2QZ;
    scalar_mul_sliced(r2QX, r2QY, r2QZ, elgamal_x, elgamal_y, w.r2_bits.bits,
                      w.r2Q);

    Flatsha sha_tag(lc_);
    const auto nb_tag = lc_.template vbit<8>(kProveVerifyRevocTagShaBlocks);
    sha_tag.assert_message(kProveVerifyRevocTagShaBlocks, nb_tag, w.tag.sha_in, w.tag.sha_bw);

    auto repack_be32 = [&](size_t ind) -> EltW {
      EltW h = lc_.konst(0);
      EltW base = lc_.konst(2);
      for (size_t i = 0; i < 32; ++i) {
        for (size_t j = 0; j < 8; ++j) {
          auto tmul = lc_.mul(h, base);
          auto bit = lc_.eval(w.tag.sha_in[ind + i][7 - j]);
          h = lc_.add(bit, tmul);
        }
      }
      return h;
    };

    EltW t2 = repack_be32(0);
    EltW r2Qx_aff = repack_be32(32);
    EltW r2Qy_aff = repack_be32(64);
    lc_.assert_eq(t2, w.t);
    lc_.assert_eq(w.t, t_pub);
    assert_equal_projective(r2QX, r2QY, r2QZ, r2Qx_aff, r2Qy_aff, one);

    lc_.vassert_eq(w.tag.sha_in[kProveVerifyRevocTagMsgBytes], lc_.template vbit<8>(0x80));
    for (size_t i = kProveVerifyRevocTagMsgBytes + 1; i < 120; ++i) {
      lc_.vassert_eq(w.tag.sha_in[i], lc_.template vbit<8>(0x00));
    }
    lc_.vassert_eq(w.tag.sha_in[126], lc_.template vbit<8>(0x02));
    lc_.vassert_eq(w.tag.sha_in[127], lc_.template vbit<8>(0x00));

    EltW tag_digest =
        repack32(sha_tag, w.tag.sha_bw[kProveVerifyRevocTagShaBlocks - 1].h1);

    Ecdsa c4_verifier(lc_, ec_, order_);
    c4_verifier.verify_signature3(w.id_x, w.id_y, tag_digest, w.c4_sig);
    lc_.assert_eq(w.c4_sig.rx, c4_rx_pub);
    lc_.assert_eq(w.c4_sig.ry, c4_ry_pub);
    lc_.assert_eq(lc_.mul(c4_s_pub, w.c4_sig.s_inv), one);

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

    auto bits_to_elt = [&](const EltW bits[kProveVerifyRevocTsBits]) -> EltW {
      EltW acc = lc_.konst(0);
      EltW twok = lc_.konst(1);
      for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) {
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

    sha.assert_message_hash(kProveVerifyRevocCredentialShaBlocks, w.credential_sha.nb,
                            w.credential_sha.sha_in, w.credential_digest_bits,
                            w.credential_sha.sha_bw);
    EltW digest_field = repack32(
        sha, w.credential_sha.sha_bw[kProveVerifyRevocCredentialShaBlocks - 1].h1);

    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[0]), w.id_x);
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[1]), w.id_y);
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[4]), birth_val);
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[5]), valid_from_val);
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[6]), valid_until_val);
    auto mk_bitw = [&](const EltW bits_lsb[kProveVerifyRevocTsBits], BitW out[kProveVerifyRevocTsBits]) {
      for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) {
        out[i] = BitW(bits_lsb[kProveVerifyRevocTsBits - 1 - i], lc_.f_);
      }
    };
    BitW b_birth[kProveVerifyRevocTsBits], b_vf[kProveVerifyRevocTsBits],
        b_vu[kProveVerifyRevocTsBits], b_now[kProveVerifyRevocTsBits],
        b_max[kProveVerifyRevocTsBits];
    mk_bitw(w.birth_bits, b_birth);
    mk_bitw(w.valid_from_bits, b_vf);
    mk_bitw(w.valid_until_bits, b_vu);
    mk_bitw(w.now_bits, b_now);
    mk_bitw(w.max_birth_bits, b_max);

    lc_.assert1(lc_.leq(kProveVerifyRevocTsBits, b_birth, b_max));
    lc_.assert1(lc_.leq(kProveVerifyRevocTsBits, b_vf, b_now));
    lc_.assert1(lc_.leq(kProveVerifyRevocTsBits, b_now, b_vu));

    Ecdsa issuer_verifier(lc_, ec_, order_);
    issuer_verifier.verify_signature3(issuer_x, issuer_y, digest_field, w.issuer_sig);

    // Packed revocation (same semantics as zk-friendly Poseidon status-list).
    lc_.assert_eq(repack_be32_from_bytes(w.attr_bytes[kProveVerifyRevocSlot]),
                  w.credential_index);

    const EltW bits_per = lc_.konst(kProveVerifyRevocBitsPerLeaf);
    const EltW packed_offset = lc_.mul(w.leaf_index, bits_per);
    lc_.assert_eq(w.credential_index, lc_.add(packed_offset, w.bit_index));

    for (auto& b : w.leaf_be) lc_.vassert_eq(b, lc_.template vbit<8>(0x00));

    auto digest_from_bw = [&](const ShaBlockWitness bw[2]) {
      std::array<v8, 32> out{};
      for (size_t j = 0; j < 8; ++j) {
        auto hj = sha.bp_.unpack_v32(bw[1].h1[j]);
        for (size_t k = 0; k < 32; ++k) {
          const size_t byte_index = (j * 4) + (3 - k / 8);
          const size_t bit_index_in_word = (k % 8);
          out[byte_index][bit_index_in_word] = hj[k];
        }
      }
      return out;
    };

    auto hash2_64bytes = [&](const std::array<v8, 32>& left,
                             const std::array<v8, 32>& right,
                             const ShaBlockWitness bw[2]) {
      v8 in[64 * kShaBlocks64];
      for (size_t i = 0; i < 32; ++i) in[i] = left[i];
      for (size_t i = 0; i < 32; ++i) in[32 + i] = right[i];
      in[64] = lc_.template vbit<8>(0x80);
      for (size_t i = 65; i < 64 * kShaBlocks64 - 8; ++i) in[i] = lc_.template vbit<8>(0x00);
      for (size_t i = 0; i < 6; ++i) in[64 * kShaBlocks64 - 8 + i] = lc_.template vbit<8>(0x00);
      in[64 * kShaBlocks64 - 2] = lc_.template vbit<8>(0x02);
      in[64 * kShaBlocks64 - 1] = lc_.template vbit<8>(0x00);
      const auto nb2 = lc_.template vbit<8>(kShaBlocks64);
      sha.assert_message(kShaBlocks64, nb2, in, bw);
      return digest_from_bw(bw);
    };

    std::array<v8, 32> cur{};
    for (size_t i = 0; i < 32; ++i) cur[i] = w.leaf_be[i];
    for (size_t d = 0; d < Depth; ++d) {
      BitW bi(w.path_idx[d], lc_.f_);
      lc_.assert_is_bit(bi);
      std::array<v8, 32> left{}, right{};
      for (size_t i = 0; i < 32; ++i) {
        lc_.vmux(bi, left[i], w.path_sib[d][i], cur[i]);
        lc_.vmux(bi, right[i], cur[i], w.path_sib[d][i]);
      }
      cur = hash2_64bytes(left, right, w.node_bw[d].data());
    }
    for (size_t i = 0; i < 32; ++i) lc_.vassert_eq(cur[i], revocation_root_pub[i]);
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

  void addE(EltW& X3, EltW& Y3, EltW& Z3, EltW X1, EltW Y1, EltW Z1, EltW X2,
            EltW Y2, EltW Z2) const {
    EltW t0 = lc_.mul(X1, X2);
    EltW t1 = lc_.mul(Y1, Y2);
    EltW t2 = lc_.mul(Z1, Z2);
    EltW t3 = lc_.add(X1, Y1);
    EltW t4 = lc_.add(X2, Y2);
    t3 = lc_.mul(t3, t4);
    t4 = lc_.add(t0, t1);
    t3 = lc_.sub(t3, t4);
    t4 = lc_.add(X1, Z1);
    EltW t5 = lc_.add(X2, Z2);
    t4 = lc_.mul(t4, t5);
    t5 = lc_.add(t0, t2);
    t4 = lc_.sub(t4, t5);
    t5 = lc_.add(Y1, Z1);
    EltW X3t = lc_.add(Y2, Z2);
    t5 = lc_.mul(t5, X3t);
    X3t = lc_.add(t1, t2);
    t5 = lc_.sub(t5, X3t);
    auto a = lc_.konst(ec_.a_);
    EltW Z3t = lc_.mul(a, t4);
    auto k3b = lc_.konst(ec_.k3b);
    X3t = lc_.mul(k3b, t2);
    Z3t = lc_.add(X3t, Z3t);
    X3t = lc_.sub(t1, Z3t);
    Z3t = lc_.add(t1, Z3t);
    EltW Y3t = lc_.mul(X3t, Z3t);
    t1 = lc_.add(t0, t0);
    t1 = lc_.add(t1, t0);
    t2 = lc_.mul(a, t2);
    t4 = lc_.mul(k3b, t4);
    t1 = lc_.add(t1, t2);
    t2 = lc_.sub(t0, t2);
    t2 = lc_.mul(a, t2);
    t4 = lc_.add(t4, t2);
    t0 = lc_.mul(t1, t4);
    Y3t = lc_.add(Y3t, t0);
    t0 = lc_.mul(t5, t4);
    X3t = lc_.mul(t3, X3t);
    X3t = lc_.sub(X3t, t0);
    t0 = lc_.mul(t3, t1);
    Z3t = lc_.mul(t5, Z3t);
    Z3t = lc_.add(Z3t, t0);

    X3 = X3t;
    Y3 = Y3t;
    Z3 = Z3t;
  }

  void doubleE(EltW& X3, EltW& Y3, EltW& Z3, EltW X, EltW Y, EltW Z) const {
    EltW t0 = lc_.mul(X, X);
    EltW t1 = lc_.mul(Y, Y);
    EltW t2 = lc_.mul(Z, Z);
    EltW t3 = lc_.mul(X, Y);
    t3 = lc_.add(t3, t3);
    EltW Z3t = lc_.mul(X, Z);
    Z3t = lc_.add(Z3t, Z3t);
    auto a = lc_.konst(ec_.a_);
    auto k3b = lc_.konst(ec_.k3b);
    EltW X3t = lc_.mul(a, Z3t);
    EltW Y3t = lc_.mul(k3b, t2);
    Y3t = lc_.add(X3t, Y3t);
    X3t = lc_.sub(t1, Y3t);
    Y3t = lc_.add(t1, Y3t);
    Y3t = lc_.mul(X3t, Y3t);
    X3t = lc_.mul(t3, X3t);
    Z3t = lc_.mul(k3b, Z3t);
    t2 = lc_.mul(a, t2);
    t3 = lc_.sub(t0, t2);
    t3 = lc_.mul(a, t3);
    t3 = lc_.add(t3, Z3t);
    Z3t = lc_.add(t0, t0);
    t0 = lc_.add(Z3t, t0);
    t0 = lc_.add(t0, t2);
    t0 = lc_.mul(t0, t3);
    Y3t = lc_.add(Y3t, t0);
    t2 = lc_.mul(Y, Z);
    t2 = lc_.add(t2, t2);
    t0 = lc_.mul(t2, t3);
    X3t = lc_.sub(X3t, t0);
    Z3t = lc_.mul(t2, t1);
    Z3t = lc_.add(Z3t, Z3t);
    Z3t = lc_.add(Z3t, Z3t);

    X3 = X3t;
    Y3 = Y3t;
    Z3 = Z3t;
  }

  const LogicCircuit& lc_;
  const EC& ec_;
  const Nat& order_;
};

template <size_t Depth>
std::unique_ptr<Circuit<Fp256Base>> make_circuit_revoc();

template <size_t Depth>
struct BenchmarkContextRevoc {
  using Field = P256Traits::Field;
  using EC = P256Traits::EC;
  using Nat = typename Field::N;
  using Field2 = Fp2<Fp256Base>;
  using Elt2 = typename Field2::Elt;
  using ConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, Field2>;
  using RSFactory = ReedSolomonFactory<Fp256Base, ConvolutionFactory>;
  using EcdsaWitness = VerifyWitness3<EC, P256Traits::Scalar>;

  static_assert(std::is_same_v<Field, Fp256Base>,
                "FFT-ext backend currently only supported for Fp256Base");

  static constexpr size_t kDepth = Depth;

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
  typename Field::Elt elgamal_pub_x;
  typename Field::Elt elgamal_pub_y;
  typename Field::Elt t_pub;
  typename Field::Elt c1x;
  typename Field::Elt c1y;
  typename Field::Elt c2x;
  typename Field::Elt c2y;
  typename Field::Elt c3x;
  typename Field::Elt c3y;
  typename Field::Elt c4_rx;
  typename Field::Elt c4_ry;
  typename Field::Elt c4_s;
  typename Field::Elt now_pub;
  typename Field::Elt max_birth_pub;

  std::array<std::array<uint8_t, 32>, kProveVerifyRevocCredentialAttrs> attr_values{};
  typename Field::Elt credential_digest_pub{};
  std::array<uint8_t, 32> credential_digest_be{};
  std::array<uint8_t, 64 * kProveVerifyRevocCredentialShaBlocks> credential_sha_in{};
  std::array<FlatSHA256Witness::BlockWitness, kProveVerifyRevocCredentialShaBlocks>
      credential_sha_bw{};

  typename Field::Elt id_x;
  typename Field::Elt id_y;
  std::array<typename Field::Elt, kProveVerifyRevocTsBits> birth_bits{};
  std::array<typename Field::Elt, kProveVerifyRevocTsBits> valid_from_bits{};
  std::array<typename Field::Elt, kProveVerifyRevocTsBits> valid_until_bits{};
  std::array<typename Field::Elt, kProveVerifyRevocTsBits> now_bits{};
  std::array<typename Field::Elt, kProveVerifyRevocTsBits> max_birth_bits{};

  std::array<uint8_t, 64 * kProveVerifyRevocTagShaBlocks> tag_sha_in{};
  std::array<FlatSHA256Witness::BlockWitness, kProveVerifyRevocTagShaBlocks> tag_sha_bw{};

  std::array<typename Field::Elt, EC::kBits> r1_bits{};
  std::array<typename Field::Elt, EC::kBits> r2_bits{};
  ScalarMulWitnessNative<EC> wit_r1G;
  ScalarMulWitnessNative<EC> wit_r2G;
  ScalarMulWitnessNative<EC> wit_r1Q;
  ScalarMulWitnessNative<EC> wit_r2Q;
  EcdsaWitness issuer_sig;
  EcdsaWitness c4_sig;

  OpenSslKeyPair issuer_key;
  OpenSslKeyPair user_key;

  uint32_t credential_index_ = 0;
  typename Field::Elt credential_index_elt{};
  typename Field::Elt leaf_index_elt{};
  typename Field::Elt bit_index_elt{};
  std::array<uint8_t, 32> revocation_root{};
  std::array<uint8_t, 32> leaf{};
  PathWitness path{};
  std::array<std::array<uint8_t, 32>, 64> level_hashes{};

  size_t show_counter_{0};
  bool credential_initialized_{false};

  explicit BenchmarkContextRevoc()
      : circuit(make_circuit_revoc<Depth>()),
        w(1, circuit->ninputs),
        field2(P256Traits::field()),
        omega(field2.of_string(kP256ExtRootX, kP256ExtRootY)),
        factory(P256Traits::field(), field2, omega, kP256ExtRootOrder),
        rsf(factory, P256Traits::field()),
        tp((uint8_t*)"pvr", 3),
        zkpr(std::make_unique<ZkProof<Field>>(*circuit, kProveVerifyRevocRate,
                                              kProveVerifyRevocQueries)),
        prover(*circuit, P256Traits::field(), rsf),
        wit_r1G(P256Traits::ec()),
        wit_r2G(P256Traits::ec()),
        wit_r1Q(P256Traits::ec()),
        wit_r2Q(P256Traits::ec()),
        issuer_sig(P256Traits::scalar_field(), P256Traits::ec()),
        c4_sig(P256Traits::scalar_field(), P256Traits::ec()),
        level_hashes(build_uniform_zero_level_hashes(Depth)) {
    set_log_level(ERROR);
    revocation_root = level_hashes[Depth];
    init_credential_once();
  }

  void init_credential_once() {
    if (credential_initialized_) return;
    const auto& field = P256Traits::field();

    check(EC_KEY_generate_key(issuer_key.key) == 1, "issuer keygen failed");
    check(EC_KEY_generate_key(user_key.key) == 1, "user keygen failed");
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

    const Nat sk = Nat(123456789);
    auto Q = P256Traits::ec().scalar_multf(P256Traits::ec().generator(), sk);
    P256Traits::ec().normalize(Q);
    elgamal_pub_x = Q.x;
    elgamal_pub_y = Q.y;

    std::array<uint8_t, 32> user_px_bytes{};
    std::array<uint8_t, 32> user_py_bytes{};
    extract_pubkey_bytes(user_key.key, user_key.group, user_px_bytes, user_py_bytes);
    id_x = field_from_be32(user_px_bytes.data());
    id_y = field_from_be32(user_py_bytes.data());

    credential_index_ = 0;
    credential_index_elt = field.of_scalar(credential_index_);
    const size_t leaf_index = credential_index_ / kProveVerifyRevocBitsPerLeaf;
    const size_t bit_index = credential_index_ % kProveVerifyRevocBitsPerLeaf;
    leaf_index_elt = field.of_scalar(leaf_index);
    bit_index_elt = field.of_scalar(bit_index);

    std::array<uint8_t, kProveVerifyRevocCredentialMsgBytes> attr_msg{};
    {
      uint8_t buf[32];
      to_bytes_be(field, id_x, buf);
      std::memcpy(&attr_msg[0 * 32], buf, 32);
      to_bytes_be(field, id_y, buf);
      std::memcpy(&attr_msg[1 * 32], buf, 32);
      to_bytes_be(field, field.to_montgomery(birth_nat), buf);
      std::memcpy(&attr_msg[4 * 32], buf, 32);
      to_bytes_be(field, field.to_montgomery(valid_from_nat), buf);
      std::memcpy(&attr_msg[5 * 32], buf, 32);
      to_bytes_be(field, field.to_montgomery(valid_until_nat), buf);
      std::memcpy(&attr_msg[6 * 32], buf, 32);
      // Same encoding as circuit bind: repack(attr[slot]) == of_scalar(index).
      to_bytes_be(field, credential_index_elt, buf);
      std::memcpy(&attr_msg[kProveVerifyRevocSlot * 32], buf, 32);
    }
    for (size_t i = 0; i < kProveVerifyRevocCredentialAttrs; ++i) {
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
    std::array<uint8_t, kProveVerifyRevocCredentialMsgBytes> leaf_msg{};
    for (size_t i = 0; i < kProveVerifyRevocCredentialAttrs; ++i) {
      uint8_t name_be[32];
      be32_index(name_be, static_cast<uint8_t>(i));
      uint8_t msg64[64];
      std::memcpy(msg64, name_be, 32);
      std::memcpy(msg64 + 32, attr_values[i].data(), 32);
      sha256_64_digest(msg64, &leaf_msg[i * 32]);
    }

    uint8_t cred_nb = 0;
    FlatSHA256Witness::transform_and_witness_message(
        kProveVerifyRevocCredentialMsgBytes, leaf_msg.data(),
        kProveVerifyRevocCredentialShaBlocks, cred_nb, credential_sha_in.data(),
        credential_sha_bw.data());
    credential_digest_pub = sha_state_to_field(
        field, credential_sha_bw[kProveVerifyRevocCredentialShaBlocks - 1].h1);
    {
      const auto& last_h = credential_sha_bw[kProveVerifyRevocCredentialShaBlocks - 1];
      for (size_t j = 0; j < 8; ++j) {
        const uint32_t w = last_h.h1[j];
        credential_digest_be[4 * j + 0] = static_cast<uint8_t>(w >> 24);
        credential_digest_be[4 * j + 1] = static_cast<uint8_t>(w >> 16);
        credential_digest_be[4 * j + 2] = static_cast<uint8_t>(w >> 8);
        credential_digest_be[4 * j + 3] = static_cast<uint8_t>(w);
      }
    }

    auto fill_bits_from_u64 = [&](std::array<typename Field::Elt, kProveVerifyRevocTsBits>& out,
                                 uint64_t x) {
      Nat n(x);
      for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) out[i] = field.of_scalar(n.bit(i));
    };
    fill_bits_from_u64(birth_bits, birth_ms);
    fill_bits_from_u64(valid_from_bits, valid_from_ms);
    fill_bits_from_u64(valid_until_bits, valid_until_ms);
    fill_bits_from_u64(max_birth_bits, max_birth_ms);

    {
      uint8_t e_be[32];
      to_bytes_be(field, credential_digest_pub, e_be);

      auto nat_from_be32 = [](const uint8_t be[32]) -> Nat {
        uint8_t le[32];
        for (size_t i = 0; i < 32; ++i) le[i] = be[31 - i];
        return Nat::of_bytes(le);
      };

      std::array<uint8_t, 32> r_be{}, s_be{};
      sign_digest_be32(issuer_key.key, e_be, r_be, s_be);

      Nat r_nat = nat_from_be32(r_be.data());
      Nat s_nat = nat_from_be32(s_be.data());

      check(issuer_sig.compute_witness(issuer_pub_x, issuer_pub_y,
                                       nat_from_be32(e_be), r_nat, s_nat),
            "issuer witness generation failed");
    }

    zero_digest(leaf);
    fill_path_for_uniform_zero_tree(Depth, leaf_index, level_hashes, path);

    credential_initialized_ = true;
  }

  void refresh_revocation_path() {
    const size_t leaf_index = credential_index_ / kProveVerifyRevocBitsPerLeaf;
    const size_t bit_index = credential_index_ % kProveVerifyRevocBitsPerLeaf;
    credential_index_elt = P256Traits::field().of_scalar(credential_index_);
    leaf_index_elt = P256Traits::field().of_scalar(leaf_index);
    bit_index_elt = P256Traits::field().of_scalar(bit_index);
    zero_digest(leaf);
    fill_path_for_uniform_zero_tree(Depth, leaf_index, level_hashes, path);
  }

  void refresh_show_inputs() {
    check(credential_initialized_, "init_credential_once() required before refresh_show_inputs()");
    ++show_counter_;
    const auto& field = P256Traits::field();

    const uint64_t base_now_ms = 1710000000000ULL;
    const uint64_t now_ms = base_now_ms + show_counter_;
    Nat now_nat(now_ms);
    now_pub = field.to_montgomery(now_nat);

    auto fill_bits_from_u64 = [&](std::array<typename Field::Elt, kProveVerifyRevocTsBits>& out,
                                 uint64_t x) {
      Nat n(x);
      for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) out[i] = field.of_scalar(n.bit(i));
    };
    fill_bits_from_u64(now_bits, now_ms);

    const Nat r1 = Nat(123456789 + show_counter_ * 1009);
    const Nat r2 = Nat(444444444 + show_counter_ * 917);
    t_pub = field.to_montgomery(Nat(7777777 + show_counter_ * 613));

    auto G = P256Traits::ec().generator();
    auto c1 = P256Traits::ec().scalar_multf(G, r1);
    auto c2 = P256Traits::ec().scalar_multf(G, r2);
    auto r1Q = P256Traits::ec().scalar_multf(
        typename EC::ECPoint{elgamal_pub_x, elgamal_pub_y, field.one()}, r1);
    auto r2Q = P256Traits::ec().scalar_multf(
        typename EC::ECPoint{elgamal_pub_x, elgamal_pub_y, field.one()}, r2);
    P256Traits::ec().normalize(c1);
    P256Traits::ec().normalize(c2);
    P256Traits::ec().normalize(r1Q);
    P256Traits::ec().normalize(r2Q);
    c1x = c1.x;
    c1y = c1.y;
    c2x = c2.x;
    c2y = c2.y;

    auto ID = typename EC::ECPoint{id_x, id_y, field.one()};
    auto c3 = P256Traits::ec().addEf(ID, r1Q);
    P256Traits::ec().normalize(c3);
    c3x = c3.x;
    c3y = c3.y;

    std::array<uint8_t, kProveVerifyRevocTagMsgBytes> tag_msg{};
    {
      uint8_t buf[32];
      to_bytes_be(field, t_pub, buf);
      std::memcpy(&tag_msg[0 * 32], buf, 32);
      to_bytes_be(field, r2Q.x, buf);
      std::memcpy(&tag_msg[1 * 32], buf, 32);
      to_bytes_be(field, r2Q.y, buf);
      std::memcpy(&tag_msg[2 * 32], buf, 32);
    }

    uint8_t tag_nb = 0;
    FlatSHA256Witness::transform_and_witness_message(
        tag_msg.size(), tag_msg.data(), kProveVerifyRevocTagShaBlocks, tag_nb,
        tag_sha_in.data(), tag_sha_bw.data());
    const typename Field::Elt tag_digest_pub =
        sha_state_to_field(field, tag_sha_bw[kProveVerifyRevocTagShaBlocks - 1].h1);

    {
      uint8_t e_be[32];
      to_bytes_be(field, tag_digest_pub, e_be);
      std::array<uint8_t, 32> r_be{}, s_be{};
      sign_digest_be32(user_key.key, e_be, r_be, s_be);
      auto nat_from_be32 = [](const uint8_t be[32]) -> Nat {
        uint8_t le[32];
        for (size_t i = 0; i < 32; ++i) le[i] = be[31 - i];
        return Nat::of_bytes(le);
      };
      Nat r_nat = nat_from_be32(r_be.data());
      Nat s_nat = nat_from_be32(s_be.data());
      const Nat e_nat = nat_from_be32(e_be);
      check(c4_sig.compute_witness(id_x, id_y, e_nat, r_nat, s_nat),
            "c4 witness generation failed");
      c4_rx = c4_sig.rx_;
      c4_ry = c4_sig.ry_;
      c4_s = field.to_montgomery(s_nat);
    }

    wit_r1G.compute(r1, G.x, G.y);
    wit_r2G.compute(r2, G.x, G.y);
    wit_r1Q.compute(r1, elgamal_pub_x, elgamal_pub_y);
    wit_r2Q.compute(r2, elgamal_pub_x, elgamal_pub_y);
    for (size_t i = 0; i < EC::kBits; ++i) r1_bits[i] = wit_r1G.bits[i];
    for (size_t i = 0; i < EC::kBits; ++i) r2_bits[i] = wit_r2G.bits[i];

    refresh_revocation_path();
  }
};

template <size_t Depth>
std::unique_ptr<Circuit<Fp256Base>> make_circuit_revoc() {
  using Field = Fp256Base;
  using EC = P256;
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltW = typename LogicCircuit::EltW;
  using v8 = typename LogicCircuit::v8;
  using CircuitT = ProveVerifyRevocationCircuit<Depth, LogicCircuit, Field, EC>;

  QuadCircuit<Field> Q(P256Traits::field());
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, P256Traits::field());
  CircuitT circuit(lc, P256Traits::ec(), n256_order);

  constexpr size_t numInstances = 1;
  std::vector<EltW> issuer_x(numInstances), issuer_y(numInstances);
  std::vector<EltW> elgamal_x(numInstances), elgamal_y(numInstances);
  std::vector<EltW> t_pub(numInstances);
  std::vector<EltW> c1x(numInstances), c1y(numInstances);
  std::vector<EltW> c2x(numInstances), c2y(numInstances);
  std::vector<EltW> c3x(numInstances), c3y(numInstances);
  std::vector<EltW> c4_rx(numInstances), c4_ry(numInstances), c4_s(numInstances);
  std::vector<EltW> now(numInstances), max_birth(numInstances);

  for (size_t i = 0; i < numInstances; ++i) {
    issuer_x[i] = lc.eltw_input();
    issuer_y[i] = lc.eltw_input();
    elgamal_x[i] = lc.eltw_input();
    elgamal_y[i] = lc.eltw_input();
    t_pub[i] = lc.eltw_input();
    c1x[i] = lc.eltw_input();
    c1y[i] = lc.eltw_input();
    c2x[i] = lc.eltw_input();
    c2y[i] = lc.eltw_input();
    c3x[i] = lc.eltw_input();
    c3y[i] = lc.eltw_input();
    c4_rx[i] = lc.eltw_input();
    c4_ry[i] = lc.eltw_input();
    c4_s[i] = lc.eltw_input();
    now[i] = lc.eltw_input();
    max_birth[i] = lc.eltw_input();
  }

  std::array<v8, 32> root_pub{};
  for (auto& b : root_pub) b = lc.template vinput<8>();

  Q.private_input();
  std::vector<typename CircuitT::Witness> ws(numInstances);
  for (size_t i = 0; i < numInstances; ++i) {
    ws[i].input(lc);
  }
  for (size_t i = 0; i < numInstances; ++i) {
    circuit.prove_relation(issuer_x[i], issuer_y[i], elgamal_x[i], elgamal_y[i],
                           t_pub[i], c1x[i], c1y[i], c2x[i], c2y[i], c3x[i],
                           c3y[i], c4_rx[i], c4_ry[i], c4_s[i], now[i], max_birth[i],
                           root_pub, ws[i]);
  }

  auto compiled = Q.mkcircuit(1);

  static std::once_flag dump_once;
  std::call_once(dump_once, [&]() { dump_info("prove_verify_revocation", numInstances, Q); });
  return compiled;
}

template <size_t Depth>
void fill_input_revoc(Dense<Fp256Base>& W, const BenchmarkContextRevoc<Depth>& ctx,
                      bool prover) {
  using EC = P256Traits::EC;
  using Field = P256Traits::Field;
  DenseFiller<Field> filler(W);

  filler.push_back(ctx.dummy_pub);
  filler.push_back(ctx.issuer_pub_x);
  filler.push_back(ctx.issuer_pub_y);
  filler.push_back(ctx.elgamal_pub_x);
  filler.push_back(ctx.elgamal_pub_y);
  filler.push_back(ctx.t_pub);
  filler.push_back(ctx.c1x);
  filler.push_back(ctx.c1y);
  filler.push_back(ctx.c2x);
  filler.push_back(ctx.c2y);
  filler.push_back(ctx.c3x);
  filler.push_back(ctx.c3y);
  filler.push_back(ctx.c4_rx);
  filler.push_back(ctx.c4_ry);
  filler.push_back(ctx.c4_s);
  filler.push_back(ctx.now_pub);
  filler.push_back(ctx.max_birth_pub);
  for (size_t i = 0; i < 32; ++i) {
    filler.push_back(ctx.revocation_root[i], 8, P256Traits::field());
  }

  if (!prover) return;

  BitPluckerEncoder<Field, kShaPluckerBits> enc(P256Traits::field());

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
  push_sig(ctx.c4_sig);

  filler.push_back(ctx.id_x);
  filler.push_back(ctx.id_y);
  filler.push_back(ctx.t_pub);
  for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) filler.push_back(ctx.birth_bits[i]);
  for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) filler.push_back(ctx.valid_from_bits[i]);
  for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) filler.push_back(ctx.valid_until_bits[i]);
  for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) filler.push_back(ctx.now_bits[i]);
  for (size_t i = 0; i < kProveVerifyRevocTsBits; ++i) filler.push_back(ctx.max_birth_bits[i]);

  for (size_t a = 0; a < kProveVerifyRevocCredentialAttrs; ++a) {
    for (size_t i = 0; i < 32; ++i) {
      filler.push_back(ctx.attr_values[a][i], 8, P256Traits::field());
    }
  }

  filler.push_back(static_cast<uint8_t>(kProveVerifyRevocCredentialShaBlocks), 8,
                   P256Traits::field());
  for (size_t i = 0; i < 64 * kProveVerifyRevocCredentialShaBlocks; ++i) {
    filler.push_back(ctx.credential_sha_in[i], 8, P256Traits::field());
  }
  for (size_t b = 0; b < kProveVerifyRevocCredentialShaBlocks; ++b) {
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
    filler.push_back(bit ? P256Traits::field().one() : P256Traits::field().zero());
  }

  for (size_t i = 0; i < EC::kBits; ++i) filler.push_back(ctx.r1_bits[i]);
  for (size_t i = 0; i < EC::kBits; ++i) filler.push_back(ctx.r2_bits[i]);

  auto push_mul_trace = [&](const ScalarMulWitnessNative<EC>& src) {
    for (size_t i = 0; i + 1 < EC::kBits; ++i) {
      filler.push_back(src.int_x[i]);
      filler.push_back(src.int_y[i]);
      filler.push_back(src.int_z[i]);
    }
  };
  push_mul_trace(ctx.wit_r1G);
  push_mul_trace(ctx.wit_r2G);
  push_mul_trace(ctx.wit_r1Q);
  push_mul_trace(ctx.wit_r2Q);

  for (size_t i = 0; i < 64 * kProveVerifyRevocTagShaBlocks; ++i) {
    filler.push_back(ctx.tag_sha_in[i], 8, P256Traits::field());
  }
  for (size_t b = 0; b < kProveVerifyRevocTagShaBlocks; ++b) {
    for (size_t k = 0; k < 48; ++k) filler.push_back(enc.mkpacked_v32(ctx.tag_sha_bw[b].outw[k]));
    for (size_t k = 0; k < 64; ++k) {
      filler.push_back(enc.mkpacked_v32(ctx.tag_sha_bw[b].oute[k]));
      filler.push_back(enc.mkpacked_v32(ctx.tag_sha_bw[b].outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) filler.push_back(enc.mkpacked_v32(ctx.tag_sha_bw[b].h1[k]));
  }

  filler.push_back(ctx.credential_index_elt);
  filler.push_back(ctx.leaf_index_elt);
  filler.push_back(ctx.bit_index_elt);
  for (size_t i = 0; i < 32; ++i) filler.push_back(ctx.leaf[i], 8, P256Traits::field());
  for (size_t d = 0; d < Depth; ++d) {
    for (size_t i = 0; i < 32; ++i) {
      filler.push_back(ctx.path.path_elements[d][i], 8, P256Traits::field());
    }
    filler.push_back(ctx.path.path_indices[d]);
  }
  for (size_t d = 0; d < Depth; ++d) push_sha64_bw(filler, ctx.path.node_bw[d]);

  if (filler.size() != W.n1_) {
    log(ERROR, "fill_input_revoc size mismatch: filled=%zu expected=%zu", filler.size(),
        W.n1_);
    check(false, "fill_input_revoc size mismatch");
  }
}

struct ProveVerifyRevocationHarnessImpl {
  virtual ~ProveVerifyRevocationHarnessImpl() = default;
  virtual void RefreshShow() = 0;
  virtual bool Prove() = 0;
  virtual void FillPublic(Dense<Fp256Base>& pub) const = 0;
  virtual bool Verify(const Dense<Fp256Base>& pub) const = 0;
  virtual size_t PublicSize() const = 0;
  virtual ZkProof<Fp256Base>& Zkpr() = 0;
};

template <size_t Depth>
class ProveVerifyRevocationHarnessT final : public ProveVerifyRevocationHarnessImpl {
 public:
  ProveVerifyRevocationHarnessT()
      : ctx_(),
        verifier_(*ctx_.circuit, ctx_.rsf, kProveVerifyRevocRate, kProveVerifyRevocQueries,
                  P256Traits::field()) {}

  void RefreshShow() override { ctx_.refresh_show_inputs(); }

  bool Prove() override {
    fill_input_revoc<Depth>(ctx_.w, ctx_, true);
    ctx_.zkpr = std::make_unique<ZkProof<Fp256Base>>(
        *ctx_.circuit, kProveVerifyRevocRate, kProveVerifyRevocQueries);
    Transcript tp((uint8_t*)"pvr", 3);
    ctx_.prover.commit(*ctx_.zkpr, ctx_.w, tp, ctx_.rng);
    return ctx_.prover.prove(*ctx_.zkpr, ctx_.w, tp);
  }

  void FillPublic(Dense<Fp256Base>& pub) const override {
    fill_input_revoc<Depth>(pub, ctx_, false);
  }

  bool Verify(const Dense<Fp256Base>& pub) const override {
    Transcript tv((uint8_t*)"pvr", 3);
    verifier_.recv_commitment(*ctx_.zkpr, tv);
    return verifier_.verify(*ctx_.zkpr, pub, tv);
  }

  size_t PublicSize() const override { return ctx_.circuit->npub_in; }

  ZkProof<Fp256Base>& Zkpr() override { return *ctx_.zkpr; }

 private:
  BenchmarkContextRevoc<Depth> ctx_;
  ZkVerifier<Fp256Base, typename BenchmarkContextRevoc<Depth>::RSFactory> verifier_;
};

}  // namespace

class ProveVerifyRevocationHarnessP256 {
 public:
  explicit ProveVerifyRevocationHarnessP256(size_t revoc_log2) {
    if (revoc_log2 == 12) {
      impl_ = std::make_unique<ProveVerifyRevocationHarnessT<5>>();
    } else if (revoc_log2 == 16) {
      impl_ = std::make_unique<ProveVerifyRevocationHarnessT<9>>();
    } else if (revoc_log2 == 20) {
      impl_ = std::make_unique<ProveVerifyRevocationHarnessT<13>>();
    } else if (revoc_log2 == 24) {
      impl_ = std::make_unique<ProveVerifyRevocationHarnessT<17>>();
    } else {
      check(false, "unsupported revoc_log2 (use 12, 16, 20, or 24)");
    }
  }

  void RefreshShow() { impl_->RefreshShow(); }
  bool Prove() { return impl_->Prove(); }
  void FillPublic(Dense<Fp256Base>& pub) const { impl_->FillPublic(pub); }
  bool Verify(const Dense<Fp256Base>& pub) const { return impl_->Verify(pub); }
  size_t PublicSize() const { return impl_->PublicSize(); }
  size_t ProofWireBytes() {
    std::vector<uint8_t> zbuf;
    impl_->Zkpr().write(zbuf, P256Traits::field());
    return zbuf.size();
  }

 private:
  std::unique_ptr<ProveVerifyRevocationHarnessImpl> impl_;
};

void ProveVerifyRevocationHarnessP256Deleter::operator()(
    ProveVerifyRevocationHarnessP256* p) const {
  delete p;
}

ProveVerifyRevocationHarnessP256Ptr MakeProveVerifyRevocationHarnessP256(
    size_t revoc_log2) {
  return ProveVerifyRevocationHarnessP256Ptr(
      new ProveVerifyRevocationHarnessP256(revoc_log2));
}

void RefreshProveVerifyRevocationShowP256(ProveVerifyRevocationHarnessP256& h) {
  h.RefreshShow();
}

bool ProveProveVerifyRevocationP256(ProveVerifyRevocationHarnessP256& h) {
  return h.Prove();
}

std::unique_ptr<Dense<Fp256Base>> PublicInputsProveVerifyRevocationP256(
    const ProveVerifyRevocationHarnessP256& h) {
  auto pub = std::make_unique<Dense<Fp256Base>>(1, h.PublicSize());
  h.FillPublic(*pub);
  return pub;
}

bool VerifyProveVerifyRevocationP256(const ProveVerifyRevocationHarnessP256& h,
                                     const Dense<Fp256Base>& pub) {
  return h.Verify(pub);
}

size_t ProofWireBytesProveVerifyRevocationP256(ProveVerifyRevocationHarnessP256& h) {
  return h.ProofWireBytes();
}

}  // namespace proofs
