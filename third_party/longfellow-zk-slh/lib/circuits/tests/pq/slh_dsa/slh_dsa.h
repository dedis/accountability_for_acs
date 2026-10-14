// SLH-DSA (FIPS 205, SHAKE parameter sets) verification as a list of
// Keccak-f calls, for a proof over copies of one hash-step circuit (not
// upstream; see slh_dsa_circuit.h and zk/zk_common.h).
//
// !!!!! DO NOT USE IN PRODUCTION !!!!!  Experimental research code.
//
// Every Keccak-f call of slh_verify (FIPS 205, Algorithm 20, pure variant)
// is one copy of the circuit in slh_dsa_circuit.h. A copy absorbs one
// 136-byte block and proves the permutation. For the second and later
// blocks of a call, the copy's private block holds the previous output XOR
// the data (rate part), and its capacity input the previous capacity. Plan walks the verification algorithm and records, for each
// copy:
//
//  - its public inputs: the constant bits of the block (PUB) and which bits
//    are private (MASK), and the flags of the copy;
//  - its private inputs (the witness), computed natively;
//  - link constraints: private bit = private bit of another copy, or
//    private bit = constant, or (later blocks) private bit = previous output
//    bit XOR (data bit or constant). They carry hash outputs, digest bits,
//    indices and chained states between copies; XOR is addition in GF(2^128),
//    so all are linear constraints on the committed witness.
//
// The copies, public inputs and links depend only on the parameter set,
// the public key, the context and the message length, never on the
// signature or the message: the verifier builds the same Plan from a zero
// signature and a zero message.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "circuits/tests/sha3/sha3_slicing.h"
#include "circuits/tests/sha3/sha3_witness.h"
#include "util/panic.h"

namespace proofs {
namespace slh_dsa {

// FIPS 205, Table 2. lg_w = 4 for all parameter sets.
template <size_t kN, size_t kH, size_t kD, size_t kA, size_t kK, size_t kM>
struct Params {
  static constexpr size_t n = kN;
  static constexpr size_t h = kH;
  static constexpr size_t d = kD;
  static constexpr size_t hp = kH / kD;  // h'
  static constexpr size_t a = kA;
  static constexpr size_t k = kK;
  static constexpr size_t m = kM;
  static constexpr size_t w = 16;
  static constexpr size_t len1 = 2 * kN;
  static constexpr size_t len2 = 3;
  static constexpr size_t len = len1 + len2;
  static constexpr size_t pk_bytes = 2 * kN;
  static constexpr size_t sig_bytes = (1 + kK * (1 + kA) + kH + kD * len) * kN;
  static_assert(kH % kD == 0, "h must be a multiple of d");
  static_assert(kH - kH / kD <= 64, "idx_tree must fit in 64 bits");
};

using SlhDsaShake192s = Params<24, 63, 7, 14, 17, 39>;
using SlhDsaShake192f = Params<24, 66, 22, 8, 33, 42>;
using SlhDsaShake256s = Params<32, 64, 8, 14, 22, 47>;
using SlhDsaShake256f = Params<32, 68, 17, 9, 35, 49>;

constexpr size_t kRate = 136;      // SHAKE256 rate in bytes
constexpr size_t kStateBits = 1600;
constexpr size_t kRateLanes = kRate / 8;     // lanes 0..16 absorb the block
constexpr size_t kCapLanes = 25 - kRateLanes;  // lanes 17..24: the capacity
constexpr size_t kAdrsBytes = 32;
constexpr size_t kAccBits = 12;    // WOTS+ checksum accumulator
constexpr size_t kSlices = 1;      // sha3_slice_at() round 23

// Inputs of one copy. Public: the constant one, PUB (1088 bits), MASK
// (1088 bits), CONT, SWAP_EN, IS_WOTS, J (4 bits), IS_ACC. Private inputs
// are numbered from the first private input (lane L is A[L % 5][L / 5]):
template <size_t kN>
struct Layout {
  // Byte offset of the two n-byte windows that SWAP exchanges; the message
  // of F and H starts there (PK.seed || ADRS || M).
  static constexpr size_t window = kN + kAdrsBytes;
  static_assert(window + 2 * kN <= kRate, "windows must fit in one block");

  static constexpr size_t npub = 1 + 2 * 8 * kRate + 8;

  static constexpr size_t cap = 0;  // lanes 17..24 of the previous output
  static constexpr size_t block = cap + 64 * kCapLanes;  // byte i bit b: 8i+b
  static constexpr size_t swap = block + 8 * kRate;
  static constexpr size_t digit = swap + 1;
  static constexpr size_t acc_in = digit + 4;
  static constexpr size_t acc_out = acc_in + kAccBits;
  static constexpr size_t r = acc_out + kAccBits;
  static constexpr size_t bw = r + 8 * kN;
  // The permutation output: the last slice of the block witness.
  static constexpr size_t sout = bw + (kSlices - 1) * kStateBits;
  static constexpr size_t npriv = bw + kSlices * kStateBits;

  // Private offset of bit B of output byte I.
  static constexpr size_t sout_bit(size_t i, size_t b) {
    return sout + ((i / 8) % 5 * 5 + (i / 8) / 5) * 64 + 8 * (i % 8) + b;
  }
};

// A private input of one copy.
struct Wire {
  uint32_t copy;
  uint32_t off;

  bool operator==(const Wire& o) const { return copy == o.copy && off == o.off; }
  bool operator!=(const Wire& o) const { return !(*this == o); }
};

// One bit of a value, with its native value.
struct Bit {
  enum Kind : uint8_t { kConst, kWire, kFree };
  Kind kind;
  bool value;
  Wire w;

  static Bit konst(bool v) { return Bit{kConst, v, Wire{0, 0}}; }
  static Bit free(bool v) { return Bit{kFree, v, Wire{0, 0}}; }
  static Bit wire(bool v, Wire w) { return Bit{kWire, v, w}; }
};

// A byte string; bit b of byte i is BITS[8i + b].
struct Val {
  std::vector<Bit> bits;

  size_t size() const { return bits.size() / 8; }
  uint8_t byte(size_t i) const {
    uint8_t x = 0;
    for (size_t b = 0; b < 8; ++b) x |= uint8_t(bits[8 * i + b].value) << b;
    return x;
  }
  void append(const Val& v) {
    bits.insert(bits.end(), v.bits.begin(), v.bits.end());
  }
  static Val konst(const uint8_t* p, size_t len) {
    Val v;
    for (size_t i = 0; i < len; ++i) {
      for (size_t b = 0; b < 8; ++b) v.bits.push_back(Bit::konst((p[i] >> b) & 1));
    }
    return v;
  }
  static Val free(const uint8_t* p, size_t len) {
    Val v;
    for (size_t i = 0; i < len; ++i) {
      for (size_t b = 0; b < 8; ++b) v.bits.push_back(Bit::free((p[i] >> b) & 1));
    }
    return v;
  }
};

// One Keccak-f call.
struct Copy {
  // Public inputs.
  uint8_t pub[kRate];
  uint8_t mask[kRate];
  bool cont, swap_en, is_wots, is_acc;
  uint8_t j;
  // Private inputs.
  uint64_t cap[kCapLanes];
  uint8_t block[kRate];
  bool swap;
  uint8_t digit;
  uint16_t acc_in, acc_out;
  uint8_t r[32];
  Sha3Witness::BlockWitness bw;
};

// Options of one hash call.
struct CallOpts {
  bool swap_en = false;
  Bit swap = Bit::konst(false);
  bool is_wots = false;
  uint8_t j = 0;
  std::array<Bit, 4> digit{Bit::konst(0), Bit::konst(0), Bit::konst(0),
                           Bit::konst(0)};
  bool is_acc = false;
  std::array<Bit, kAccBits> acc_in{};
};

// FIPS 205 address types.
enum AdrsType : uint32_t {
  kWotsHash = 0,
  kWotsPk = 1,
  kTree = 2,
  kForsTree = 3,
  kForsRoots = 4,
};

template <class P>
class Plan {
  using L = Layout<P::n>;

 public:
  std::vector<Copy> copies;
  std::vector<std::pair<Wire, Wire>> eq;     // a == b
  std::vector<std::pair<Wire, bool>> fixed;  // a == constant
  std::vector<std::array<Wire, 3>> sum;      // a == b xor c
  std::vector<std::pair<std::pair<Wire, Wire>, bool>> sum_fixed;  // a == b xor constant
  bool native_ok = false;  // the native verification accepted

  // PK: 2n bytes. MSG: the message, private; only its length is public.
  // SIG: sig_bytes bytes, private. The verifier passes zeros for both.
  Plan(const std::vector<uint8_t>& pk, const std::vector<uint8_t>& ctx,
       const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig) {
    size_t slices = 0;
    for (size_t round = 0; round < 24; ++round) slices += sha3_slice_at(round);
    check(slices == kSlices, "unexpected SHA3 slicing");
    // FIPS 205 Alg. 24: a wrong length does not verify (no copies).
    if (!valid_statement(pk, ctx) || sig.size() != P::sig_bytes) return;
    verify(pk, ctx, msg, sig);
  }

  // True if PK and CTX have valid lengths (FIPS 205 Alg. 24).
  static bool valid_statement(const std::vector<uint8_t>& pk,
                              const std::vector<uint8_t>& ctx) {
    return pk.size() == P::pk_bytes && ctx.size() <= 255;
  }

  // Native value of a private input.
  bool value(const Wire& w) const {
    const Copy& cp = copies.at(w.copy);
    const size_t off = w.off;
    auto lane_bit = [](const uint64_t lanes[5][5], size_t i) {
      const size_t lane = i / 64;
      return bool((lanes[lane / 5][lane % 5] >> (i % 64)) & 1);
    };
    if (off < L::block) return (cp.cap[off / 64] >> (off % 64)) & 1;
    if (off < L::swap) {
      return (cp.block[(off - L::block) / 8] >> ((off - L::block) % 8)) & 1;
    }
    if (off == L::swap) return cp.swap;
    if (off < L::acc_in) return (cp.digit >> (off - L::digit)) & 1;
    if (off < L::acc_out) return (cp.acc_in >> (off - L::acc_in)) & 1;
    if (off < L::r) return (cp.acc_out >> (off - L::acc_out)) & 1;
    if (off < L::bw) return (cp.r[(off - L::r) / 8] >> ((off - L::r) % 8)) & 1;
    check(off < L::npriv, "private input offset");
    const size_t slice = (off - L::bw) / kStateBits;
    size_t round = 0, seen = 0;
    for (; round < 24; ++round) {
      if (sha3_slice_at(round) && seen++ == slice) break;
    }
    return lane_bit(cp.bw.a_intermediate[round], (off - L::bw) % kStateBits);
  }

 private:
  Val seed_, root_;

  // Wire references to the first NBYTES output bytes of copy C.
  Val output(size_t c, size_t nbytes) const {
    Val v;
    for (size_t i = 0; i < nbytes; ++i) {
      for (size_t b = 0; b < 8; ++b) {
        const size_t off = L::sout_bit(i, b);
        v.bits.push_back(Bit::wire(bit_of(copies[c], off), wire(c, off)));
      }
    }
    return v;
  }

  // Wire references to the n-byte result R of copy C.
  Val result(size_t c) const {
    Val v;
    for (size_t i = 0; i < 8 * P::n; ++i) {
      v.bits.push_back(Bit::wire((copies[c].r[i / 8] >> (i % 8)) & 1,
                                 wire(c, L::r + i)));
    }
    return v;
  }

  static Wire wire(size_t c, size_t off) {
    return Wire{static_cast<uint32_t>(c), static_cast<uint32_t>(off)};
  }

  static bool bit_of(const Copy& cp, size_t off) {
    check(off >= L::sout && off < L::npriv, "only output bits are read back");
    const size_t i = off - L::sout;
    const size_t lane = i / 64;
    return (cp.bw.a_intermediate[23][lane / 5][lane % 5] >> (i % 64)) & 1;
  }

  // Constrains private input OFF of copy C to BIT.
  void link(size_t c, size_t off, const Bit& bit) {
    if (bit.kind == Bit::kWire) {
      eq.push_back({wire(c, off), bit.w});
    } else if (bit.kind == Bit::kConst) {
      fixed.push_back({wire(c, off), bit.value});
    }
  }

  // Absorbs INPUT (SHAKE256-padded here) into one copy per block and
  // returns the index of the last copy. The windows of the first block are
  // swapped when OPTS.swap is set.
  size_t call(const Val& input, const CallOpts& opts) {
    const size_t len = input.size();
    const size_t nblocks = len / kRate + 1;
    check(nblocks == 1 || (!opts.swap_en && !opts.is_wots && !opts.is_acc),
          "multi-block calls have no options");
    size_t last = 0;
    for (size_t blk = 0; blk < nblocks; ++blk) {
      last = copies.size();
      copies.push_back(Copy{});
      Copy& cp = copies.back();
      cp.cont = blk > 0;
      cp.swap_en = opts.swap_en;
      cp.is_wots = opts.is_wots;
      cp.is_acc = opts.is_acc;
      cp.j = opts.j;
      for (size_t i = 0; i < kRate; ++i) {
        const size_t pos = blk * kRate + i;
        for (size_t b = 0; b < 8; ++b) {
          Bit bit = Bit::konst(false);
          if (pos < len) {
            bit = input.bits[8 * pos + b];
          } else {
            // pad10*1 with the SHAKE domain bits: 0x1F, then 0x80 at the end.
            const uint8_t pad = (pos == len ? 0x1F : 0) |
                                (i == kRate - 1 ? 0x80 : 0);
            bit = Bit::konst((pad >> b) & 1);
          }
          const Wire w = wire(last, L::block + 8 * i + b);
          if (cp.cont) {
            // Previous output XOR data, all private.
            const Wire prev = wire(last - 1, L::sout_bit(i, b));
            const bool prev_value = bit_of(copies[last - 1], prev.off);
            cp.mask[i] |= uint8_t(1) << b;
            cp.block[i] |= uint8_t(prev_value ^ bit.value) << b;
            if (bit.kind == Bit::kConst) {
              sum_fixed.push_back({{w, prev}, bit.value});
            } else if (bit.kind == Bit::kWire) {
              sum.push_back({w, prev, bit.w});
            }
          } else if (bit.kind == Bit::kConst) {
            cp.pub[i] |= uint8_t(bit.value) << b;
          } else {
            cp.mask[i] |= uint8_t(1) << b;
            cp.block[i] |= uint8_t(bit.value) << b;
            link(last, L::block + 8 * i + b, bit);
          }
        }
      }

      cp.swap = opts.swap.value;
      if (opts.swap_en) link(last, L::swap, opts.swap);
      if (opts.is_wots) {
        for (size_t b = 0; b < 4; ++b) {
          cp.digit |= uint8_t(opts.digit[b].value) << b;
          link(last, L::digit + b, opts.digit[b]);
        }
      }
      if (opts.is_acc) {
        for (size_t b = 0; b < kAccBits; ++b) {
          cp.acc_in |= uint16_t(opts.acc_in[b].value) << b;
          link(last, L::acc_in + b, opts.acc_in[b]);
        }
        cp.acc_out = cp.acc_in + (15 - cp.digit);
      }

      // State before the permutation, as the circuit computes it: the
      // capacity of the previous output, and the block in the rate lanes.
      uint64_t A[5][5] = {};
      if (cp.cont) {
        const Copy& prev = copies[last - 1];
        for (size_t j = 0; j < kCapLanes; ++j) {
          const size_t lane = kRateLanes + j;
          const size_t x = lane % 5, y = lane / 5;
          cp.cap[j] = prev.bw.a_intermediate[23][x][y];
          A[x][y] = cp.cap[j];
          for (size_t b = 0; b < 64; ++b) {
            eq.push_back({wire(last, L::cap + 64 * j + b),
                          wire(last - 1, L::sout + (x * 5 + y) * 64 + b)});
          }
        }
      }
      uint8_t data[kRate];
      std::memcpy(data, cp.block, kRate);
      if (cp.swap_en && cp.swap) {
        for (size_t i = 0; i < P::n; ++i) {
          data[L::window + i] = cp.block[L::window + P::n + i];
          data[L::window + P::n + i] = cp.block[L::window + i];
        }
      }
      for (size_t i = 0; i < kRate; ++i) {
        const uint8_t byte = cp.pub[i] ^ (cp.mask[i] & data[i]);
        const size_t lane = i / 8;
        A[lane % 5][lane / 5] ^= uint64_t(byte) << (8 * (i % 8));
      }
      Sha3Witness::compute_witness_block(A, cp.bw);

      const bool active = !cp.is_wots || cp.j >= cp.digit;
      for (size_t i = 0; i < P::n; ++i) {
        const size_t lane = i / 8;
        const uint8_t out =
            static_cast<uint8_t>(A[lane % 5][lane / 5] >> (8 * (i % 8)));
        cp.r[i] = active ? out : cp.block[L::window + i];
      }
    }
    return last;
  }

  // ADRS with constant words, before the variable fields are set.
  static Val adrs(uint32_t layer, uint32_t type, uint32_t w1, uint32_t w2,
                  uint32_t w3) {
    uint8_t a[kAdrsBytes] = {};
    put32(a, 0, layer);
    put32(a, 16, type);
    put32(a, 20, w1);
    put32(a, 24, w2);
    put32(a, 28, w3);
    return Val::konst(a, kAdrsBytes);
  }

  static void put32(uint8_t* a, size_t off, uint32_t x) {
    for (size_t i = 0; i < 4; ++i) a[off + i] = uint8_t(x >> (24 - 8 * i));
  }

  // Writes the integer with bits BITS (LSB first) big-endian into the
  // NBYTES bytes of V at OFF; higher bits are zero.
  static void put_be(Val& v, size_t off, size_t nbytes,
                     const std::vector<Bit>& bits) {
    for (size_t t = 0; t < 8 * nbytes; ++t) {
      v.bits[8 * (off + nbytes - 1 - t / 8) + t % 8] =
          t < bits.size() ? bits[t] : Bit::konst(false);
    }
  }

  // Bits [lo, hi) of BITS, then zeros, LSB first.
  static std::vector<Bit> range(const std::vector<Bit>& bits, size_t lo,
                                size_t hi) {
    std::vector<Bit> r;
    for (size_t t = lo; t < hi; ++t) {
      r.push_back(t < bits.size() ? bits[t] : Bit::konst(false));
    }
    return r;
  }

  static Val cat(std::initializer_list<const Val*> parts) {
    Val v;
    for (const Val* p : parts) v.append(*p);
    return v;
  }

  // F or H: PK.seed || ADRS || M.
  size_t hash(const Val& adrs, const Val& m, const CallOpts& opts) {
    return call(cat({&seed_, &adrs, &m}), opts);
  }

  // Algorithm 20 (slh_verify_internal) on M' = 0x00 || |ctx| || ctx || M.
  void verify(const std::vector<uint8_t>& pk, const std::vector<uint8_t>& ctx,
              const std::vector<uint8_t>& msg,
              const std::vector<uint8_t>& sig) {
    constexpr size_t n = P::n, a = P::a, k = P::k, hp = P::hp;
    seed_ = Val::konst(pk.data(), n);
    root_ = Val::konst(pk.data() + n, n);
    size_t at = 0;  // signature cursor
    auto take = [&](size_t len) {
      Val v = Val::free(sig.data() + at, len);
      at += len;
      return v;
    };

    // digest = H_msg(R, PK.seed, PK.root, M')
    const Val R = take(n);
    std::vector<uint8_t> head = {0, static_cast<uint8_t>(ctx.size())};
    head.insert(head.end(), ctx.begin(), ctx.end());
    const Val head_v = Val::konst(head.data(), head.size());
    const Val msg_v = Val::free(msg.data(), msg.size());
    const size_t hmsg = call(cat({&R, &seed_, &root_, &head_v, &msg_v}), {});
    const Val digest = output(hmsg, P::m);

    // Split the digest (Algorithm 20, steps 7-10).
    constexpr size_t ka_bytes = (k * a + 7) / 8;
    constexpr size_t tree_bits = P::h - hp;
    constexpr size_t tree_bytes = (tree_bits + 7) / 8;
    constexpr size_t leaf_bytes = (hp + 7) / 8;
    static_assert(ka_bytes + tree_bytes + leaf_bytes == P::m, "digest size");
    auto be_bits = [&](size_t off, size_t nbytes, size_t nbits) {
      std::vector<Bit> bits;
      for (size_t t = 0; t < nbits; ++t) {
        bits.push_back(digest.bits[8 * (off + nbytes - 1 - t / 8) + t % 8]);
      }
      return bits;
    };
    const std::vector<Bit> idx_tree = be_bits(ka_bytes, tree_bytes, tree_bits);
    const std::vector<Bit> idx_leaf =
        be_bits(ka_bytes + tree_bytes, leaf_bytes, hp);

    // FORS (Algorithm 17, fors_pkFromSig).
    Val roots;
    for (size_t i = 0; i < k; ++i) {
      // indices[i]: bits i*a .. i*a + a - 1 of md, most significant first.
      std::vector<Bit> md_i(a);
      for (size_t v = 0; v < a; ++v) {
        const size_t p = i * a + (a - 1 - v);
        md_i[v] = digest.bits[8 * (p / 8) + (7 - p % 8)];
      }
      // Tree index (i * 2^a + indices[i]) >> z.
      auto tree_index = [&](size_t z) {
        std::vector<Bit> bits;
        for (size_t t = 0; t < 32; ++t) {
          const size_t s = t + z;
          bits.push_back(s < a ? md_i[s] : Bit::konst((i >> (s - a)) & 1));
        }
        return bits;
      };
      Val ad = adrs(0, kForsTree, 0, 0, 0);
      put_be(ad, 4, 12, idx_tree);
      put_be(ad, 20, 4, idx_leaf);
      put_be(ad, 28, 4, tree_index(0));
      const Val sk = take(n);
      Val node = result(hash(ad, sk, {}));
      for (size_t z = 0; z < a; ++z) {
        Val adz = adrs(0, kForsTree, 0, uint32_t(z + 1), 0);
        put_be(adz, 4, 12, idx_tree);
        put_be(adz, 20, 4, idx_leaf);
        put_be(adz, 28, 4, tree_index(z + 1));
        const Val auth = take(n);
        CallOpts o;
        o.swap_en = true;
        o.swap = md_i[z];
        node = result(hash(adz, cat({&node, &auth}), o));
      }
      roots.append(node);
    }
    Val ad_roots = adrs(0, kForsRoots, 0, 0, 0);
    put_be(ad_roots, 4, 12, idx_tree);
    put_be(ad_roots, 20, 4, idx_leaf);
    Val node = result(hash(ad_roots, roots, {}));

    // Hypertree (Algorithm 13, ht_verify).
    for (size_t l = 0; l < P::d; ++l) {
      const std::vector<Bit> tree = range(idx_tree, l * hp, tree_bits);
      const std::vector<Bit> leaf =
          l == 0 ? idx_leaf : range(idx_tree, (l - 1) * hp, l * hp);
      node = xmss(uint32_t(l), tree, leaf, node, take);
    }
    check(at == sig.size(), "signature not consumed");

    // node == PK.root
    native_ok = true;
    for (size_t t = 0; t < 8 * n; ++t) {
      fixed.push_back({node.bits[t].w, root_.bits[t].value});
      native_ok &= node.bits[t].value == root_.bits[t].value;
    }
  }

  // Algorithm 11 (xmss_pkFromSig) with Algorithm 8 (wots_pkFromSig).
  template <class Take>
  Val xmss(uint32_t layer, const std::vector<Bit>& tree,
           const std::vector<Bit>& leaf, const Val& msg, Take& take) {
    constexpr size_t n = P::n, hp = P::hp;
    auto wots_adrs = [&](uint32_t type, uint32_t chain, uint32_t hash_addr) {
      Val ad = adrs(layer, type, 0, chain, hash_addr);
      put_be(ad, 4, 12, tree);
      put_be(ad, 20, 4, leaf);
      return ad;
    };

    // base_2b(msg, 4, len1): high nibble first.
    std::vector<std::array<Bit, 4>> digits(P::len);
    for (size_t i = 0; i < P::len1; ++i) {
      for (size_t q = 0; q < 4; ++q) {
        digits[i][q] = msg.bits[8 * (i / 2) + q + (i % 2 == 0 ? 4 : 0)];
      }
    }

    Val pks;
    std::array<Bit, kAccBits> acc{};
    for (auto& b : acc) b = Bit::konst(false);
    for (size_t i = 0; i < P::len; ++i) {
      if (i == P::len1) {
        // csum << 4, as 2 bytes, in 3 nibbles: the nibbles of csum.
        for (size_t t = 0; t < P::len2; ++t) {
          for (size_t q = 0; q < 4; ++q) {
            digits[i + t][q] = acc[4 * (P::len2 - 1 - t) + q];
          }
        }
      }
      Val x = take(n);
      for (uint8_t j = 0; j + 1 < P::w; ++j) {
        CallOpts o;
        o.is_wots = true;
        o.j = j;
        o.digit = digits[i];
        o.is_acc = j == 0 && i < P::len1;
        o.acc_in = acc;
        const size_t c = hash(wots_adrs(kWotsHash, uint32_t(i), j), x, o);
        x = result(c);
        if (o.is_acc) {
          for (size_t b = 0; b < kAccBits; ++b) {
            acc[b] = Bit::wire((copies[c].acc_out >> b) & 1,
                               wire(c, L::acc_out + b));
          }
        }
      }
      pks.append(x);
    }
    Val node = result(hash(wots_adrs(kWotsPk, 0, 0), pks, {}));

    for (size_t z = 0; z < hp; ++z) {
      Val ad = adrs(layer, kTree, 0, uint32_t(z + 1), 0);
      put_be(ad, 4, 12, tree);
      put_be(ad, 28, 4, range(leaf, z + 1, hp));
      const Val auth = take(n);
      CallOpts o;
      o.swap_en = true;
      o.swap = leaf[z];
      node = result(hash(ad, cat({&node, &auth}), o));
    }
    return node;
  }
};

}  // namespace slh_dsa
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_SLH_DSA_SLH_DSA_H_
