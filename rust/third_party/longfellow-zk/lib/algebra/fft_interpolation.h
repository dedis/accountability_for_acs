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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FFT_INTERPOLATION_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FFT_INTERPOLATION_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "algebra/blas.h"
#include "algebra/twiddle.h"
#include "util/panic.h"

namespace proofs {
template <class Field>
class FFTInterpolation {
  using Elt = typename Field::Elt;

  // Know a0, a1 want b0, b1
  // Note winv = w^{-1}
  static void a0a1(const Elt* A, Elt* B, size_t s, const Elt& winv,
                   const Field& F) {
    Elt x0 = A[0];
    Elt x1 = F.mulf(A[s], winv);
    B[0] = F.addf(x0, x1);
    B[s] = F.subf(x0, x1);
  }

  static void a0a1(const Elt* A, Elt* B, size_t s, const Field& F) {
    Elt x0 = A[0];
    Elt x1 = A[s];
    B[0] = F.addf(x0, x1);
    B[s] = F.subf(x0, x1);
  }

  // know b0, b1 want a0, a1
  static void b0b1(Elt* A, const Elt* B, size_t s, const Elt& w,
                   const Field& F) {
    Elt x0 = F.mulf(F.half(), F.addf(B[0], B[s]));
    Elt x1 = F.mulf(F.half(), F.subf(B[0], B[s]));
    A[0] = x0;
    A[s] = F.mulf(x1, w);
  }

  static void b0b1_unscaled(Elt* A, const Elt* B, size_t s, const Elt& w,
                            const Field& F) {
    Elt x0 = F.addf(B[0], B[s]);
    Elt x1 = F.subf(B[0], B[s]);
    A[0] = x0;
    A[s] = F.mulf(x1, w);
  }
  static void b0b1_unscaled(Elt* A, const Elt* B, size_t s, const Field& F) {
    Elt x0 = F.addf(B[0], B[s]);
    Elt x1 = F.subf(B[0], B[s]);
    A[0] = x0;
    A[s] = x1;
  }

  // know: a0 and b0, want a1 and b1
  // x0 = a0
  // x1 = a1 * w^{-1}
  // b0 = x0 + x1
  // b1 = x0 - x1
  static void a0b0(Elt* A, Elt* B, size_t s, const Elt& w, const Field& F) {
    Elt x0 = A[0];
    Elt x1 = F.subf(B[0], x0);
    A[s] = F.mulf(x1, w);
    B[s] = F.subf(x0, x1);
  }

  // know: a0 and b1, want a1 and b0
  // x0 = a0
  // x1 = a1 * w^{-1}
  // b0 = x0 + x1
  // b1 = x0 - x1
  static void a0b1(Elt* A, Elt* B, size_t s, const Elt& w, const Field& F) {
    Elt x0 = A[0];
    Elt x1 = F.subf(x0, B[s]);
    A[s] = F.mulf(x1, w);
    B[0] = F.addf(x0, x1);
  }

  // B -> A
  static void fftb(Elt A[/*n*/], const Elt B[/*n*/], size_t n,
                   const Twiddle<Field>& roots, const Field& F) {
    for (size_t j = 0; j < n; ++j) {
      A[j] = B[j];
    }

    Elt scale = F.one();

    for (size_t m = n; m > 2;) {
      m /= 2;
      size_t ws = roots.order_ / (2 * m);
      for (size_t k = 0; k < n; k += 2 * m) {
        b0b1_unscaled(&A[k], &A[k], m, F);  // j == 0
        for (size_t j = 1; j < m; ++j) {
          b0b1_unscaled(&A[k + j], &A[k + j], m, roots.w_[j * ws], F);
        }
      }
      F.mul(scale, F.half());
    }

    if (n >= 2) {
      for (size_t k = 0; k < n; k += 2) {
        b0b1_unscaled(&A[k], &A[k], 1, F);
      }
      F.mul(scale, F.half());
    }

    Blas<Field>::scale(n, A, 1, scale, F);
  }

  // A -> B
  static void fftf(const Elt A[/*n*/], Elt B[/*n*/], size_t n,
                   const Twiddle<Field>& rootsinv, const Field& F) {
    for (size_t j = 0; j < n; ++j) {
      B[j] = A[j];
    }

    // m = 1
    if (n >= 2) {
      for (size_t k = 0; k < n; k += 2) {
        a0a1(&B[k], &B[k], 1, F);
      }
    }

    // m > 1
    for (size_t m = 2; m < n; m = 2 * m) {
      size_t ws = rootsinv.order_ / (2 * m);
      for (size_t k = 0; k < n; k += 2 * m) {
        a0a1(&B[k], &B[k], m, F);  // j = 0
        for (size_t j = 1; j < m; ++j) {
          a0a1(&B[k + j], &B[k + j], m, rootsinv.w_[j * ws], F);
        }
      }
    }
  }

  static bool in_range(size_t j, size_t b0, size_t n, size_t k) {
    size_t b1 = b0 + (n - k);
    return (b0 <= j && j < b1) || (b0 <= j + n && j + n < b1);
  }

  // This is a generalization of the truncated FFT algorithm described
  // in Joris van der Hoeven, "The Truncated Fourier Transform and
  // Applications".  See also the followup paper "Notes on the
  // Truncated Fourier Transform", also by Joris van der Hoeven.

  // Define arbitrarily an "evaluation" domain A and a "coefficient"
  // domain B.  The "forward" FFT computes the cofficients B given
  // evaluations A, and the "backward" FFT computes the evaluations A
  // given the coefficients B.  By convention, the evaluations A are in
  // bit-reversed order, and we put the 1/N normalization on
  // the backward side.

  // Given inputs
  //
  //    A[j] for 0 <= j < k
  //    B[j % n] for b0 <= j < b0 + (n - k)
  //
  // this function fills the rest of A[] and B[], so that at the
  // end B = fftf(A) and A = fftb(B).
  static void bidir(size_t n, Elt A[/*n*/], Elt B[/*n*/], size_t k, size_t b0,
                    const Twiddle<Field>& roots, const Twiddle<Field>& rootsinv,
                    Elt workspace[/*2*n*/], const Field& F) {
    check(k <= n, "k <= n");
    check(b0 < n, "b0 < n");

    if (k == 0) {
      fftb(A, B, n, roots, F);
    } else if (k == n) {
      fftf(A, B, n, rootsinv, F);
    } else if (n > 1) {
      size_t ws = roots.order_ / n;
      size_t n2 = n / 2;

      // allocate T from workspace
      Elt* T = workspace;
      workspace += n;

      if (k >= n2) {
        // first half A -> T
        fftf(A, &T[0], n2, rootsinv, F);

        // diagonal butterflies T <-> B
        for (size_t j = 0; j < n2; ++j) {
          if (in_range(j, b0, n, k)) {
            if (in_range(j + n2, b0, n, k)) {
              // can't happen because the range is < n2
              check(false, "can't happen");
            } else {
              a0b0(&T[j], &B[j], n2, roots.w_[j * ws], F);
            }
          } else {
            if (in_range(j + n2, b0, n, k)) {
              a0b1(&T[j], &B[j], n2, roots.w_[j * ws], F);
            } else {
              // done below
            }
          }
        }

        // second half A <-> T
        size_t bb0 = (b0 >= n2) ? (b0 - n2) : b0;
        bidir(n2, &A[n2], &T[n2], k - n2, bb0, roots, rootsinv, workspace, F);

        // forward butterflies T -> B
        for (size_t j = 0; j < n2; ++j) {
          if (in_range(j, b0, n, k)) {
            if (in_range(j + n2, b0, n, k)) {
              // can't happen because the range is < n2
              check(false, "can't happen");
            } else {
              // done above
            }
          } else {
            if (in_range(j + n2, b0, n, k)) {
              // done above
            } else {
              a0a1(&T[j], &B[j], n2, rootsinv.w_[j * ws], F);
            }
          }
        }
      } else {
        // backward butterflies B -> T
        for (size_t j = 0; j < n2; ++j) {
          if (in_range(j, b0, n, k)) {
            if (in_range(j + n2, b0, n, k)) {
              b0b1(&T[j], &B[j], n2, roots.w_[j * ws], F);
            } else {
              // done below
            }
          } else {
            // done below
          }
        }

        // first half A <-> T
        size_t bb0 = (b0 >= n2) ? (b0 - n2) : b0;
        bidir(n2, &A[0], &T[0], k, bb0, roots, rootsinv, workspace, F);

        // diagonal butterflies T <-> B
        for (size_t j = 0; j < n2; ++j) {
          if (in_range(j, b0, n, k)) {
            if (in_range(j + n2, b0, n, k)) {
              // done above
            } else {
              a0b0(&T[j], &B[j], n2, roots.w_[j * ws], F);
            }
          } else {
            if (in_range(j + n2, b0, n, k)) {
              a0b1(&T[j], &B[j], n2, roots.w_[j * ws], F);
            } else {
              // can't happen.  Range is >= n2 so
              // either j or j+n2 is in range
              check(false, "can't happen");
            }
          }
        }

        // second half T -> A
        fftb(&A[n2], &T[n2], n2, roots, F);
      }
    }
  }

 public:
  static void interpolate(size_t n, Elt A[/*n*/], Elt B[/*n*/], size_t k,
                          size_t b0, const Elt& omega_m, uint64_t m,
                          const Field& F) {
    if (n > 1) {
      Elt omega_n = Twiddle<Field>::reroot(omega_m, m, n, F);
      Twiddle<Field> roots(n, omega_n, F);
      Twiddle<Field> rootsinv(n, F.invertf(omega_n), F);
      std::vector<Elt> workspace(2 * n);
      bidir(n, A, B, k, b0, roots, rootsinv, &workspace[0], F);
    } else if (n == 1) {
      // Twiddle(n) fails because of vector of size 0.
      // Compute the answer directly.
      if (k == 0) {
        A[0] = B[0];
      } else {
        B[0] = A[0];
      }
    }
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FFT_INTERPOLATION_H_
