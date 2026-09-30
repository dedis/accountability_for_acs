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

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_NUSSBAUMER_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_NUSSBAUMER_H_

#include <stddef.h>

#include <vector>

#include "algebra/permutations.h"

// Various forms of convolution.
namespace proofs {

template <class Field>
class Nussbaumer {
 public:
  typedef typename Field::Elt Elt;
  static constexpr size_t kNussbaumerSmall = 64;
  static constexpr size_t kKaratsubaSmall = 4;

  // Nussbaumer's negacyclic convolution. See Knuth TAOCP 4.6.4
  // Exercise 59.
  //
  // The algorithm is relatively straightforward but the
  // implementation is complicated by our desire to minimize space
  // requirements.  We split the algorithm into three nested layers:
  // negacyclic() allocates temporary memory;
  // negacyclic_with_workspace() "lifts" the negacyclic convolution
  // into a linear convolution via zero-padding and transposition;
  // negacyclic_lifted() performs a lifted convolution via FFT.
  //
  // Other routines, such as linear() and middle(), allocate their own
  // memory and/or do their own lifting, and thus they enter the
  // negacyclic algorithm at different places.
  //
  static void negacyclic(size_t n, Elt z[/*n*/], const Elt x[/*n*/],
                         const Elt y[/*n*/], const Field& F) {
    if (n <= kNussbaumerSmall) {
      karatsuba_negacyclic(n, z, x, y, F);
    } else {
      std::vector<Elt> X(2 * n);
      std::vector<Elt> Y(2 * n);
      std::vector<Elt> Z(2 * n);

      negacyclic_with_workspace(n, z, x, y, Z.data(), X.data(), Y.data(), F);
    }
  }

  static void linear(size_t n, Elt z[/*2*n*/], const Elt x[/*n*/],
                     const Elt y[/*n*/], const Field& F) {
    if (n <= kNussbaumerSmall) {
      karatsuba(n, z, x, y, F);
    } else {
      // workspace for both cyclic and negacyclic
      std::vector<Elt> X(2 * n);
      std::vector<Elt> Y(2 * n);
      std::vector<Elt> Z(2 * n);

      for (size_t i = 0; i < n; ++i) {
        X[i] = x[i];
        Y[i] = y[i];
      }
      cyclic_with_workspace(n, z, X.data(), Y.data(), &Z[n], &X[n], &Y[n], F);

      negacyclic_with_workspace(n, z + n, x, y, X.data(), Y.data(), Z.data(),
                                F);

      for (size_t i = 0; i < n; ++i) {
        inverse_butterfly(z + i, z + n + i, F);
      }
    }
  }

  // "middle-product" variant z[k] = sum_j x[n+k-j]*y[j]
  //
  // Note Z[N], X[2*N], Y[N].  For fixed Y, linear() computes a
  // linear function X->Z, and middle() computes the transpose
  // function.

  static void middle(size_t n, Elt z[/*n*/], const Elt x[/*2*n*/],
                     const Elt y[/*n*/], const Field& F) {
    if (n <= kNussbaumerSmall) {
      basecase_middle(n, z, x, y, F);
    } else {
      std::vector<Elt> X(2 * n);
      std::vector<Elt> Y(2 * n);
      std::vector<Elt> Z(2 * n);

      for (size_t i = 0; i < n; ++i) {
        // use copy of Y because cyclic() destroys the input
        X[i] = F.addf(x[i], x[i + n]);
        Y[i] = y[i];
      }
      cyclic_with_workspace(n, z, X.data(), Y.data(), &Z[n], &X[n], &Y[n], F);

      size_t m, r;
      choose_radix(&m, &r, n);

      // combined half-butterfly and lift() of X
      for (size_t i = 0; i < m; ++i) {
        for (size_t j = 0; j < r; ++j) {
          X[r * i + j] = F.subf(x[m * j + i], x[m * j + i + n]);
        }
      }

      lift(Y.data(), y, m, r);
      negacyclic_lifted(m, r, Z.data(), X.data(), Y.data(), F);

      // combined inverse half-butterfly and unlift() of Z
      for (size_t i = 0; i < m; ++i) {
        for (size_t j = 0; j < r; ++j) {
          F.sub(z[m * j + i], Z[r * i + j]);
          F.mul(z[m * j + i], F.half());
        }
      }
    }
  }

 private:
  static void butterfly(Elt* a0, Elt* a1, const Field& F) {
    Elt t = *a1;
    *a1 = *a0;
    F.add(*a0, t);
    F.sub(*a1, t);
  }

  static void inverse_butterfly(Elt* a0, Elt* a1, const Field& F) {
    Elt t = *a1;
    *a1 = *a0;
    F.add(*a0, t);
    F.mul(*a0, F.half());
    F.sub(*a1, t);
    F.mul(*a1, F.half());
  }

  static void negate(Elt* x, size_t n, const Field& F) {
    for (size_t i = 0; i < n; ++i) {
      F.neg(x[i]);
    }
  }

  static void negacyclic_with_workspace(size_t n, Elt z[/*n*/],
                                        const Elt x[/*n*/], const Elt y[/*n*/],
                                        Elt Z[/*2*n*/], Elt X[/*2*n*/],
                                        Elt Y[/*2*n*/], const Field& F) {
    size_t m, r;
    choose_radix(&m, &r, n);

    lift(X, x, m, r);
    lift(Y, y, m, r);
    negacyclic_lifted(m, r, Z, X, Y, F);
    unlift(Z, z, m, r);
  }

  static void negacyclic_lifted(size_t m, size_t r, Elt* Z, Elt* X, Elt* Y,
                                const Field& F) {
    zerolift(X, m, r, F);
    fft(X, 2 * m, r, F);

    zerolift(Y, m, r, F);
    fft(Y, 2 * m, r, F);

    for (size_t i = 0; i < 2 * m; i++) {
      negacyclic(r, Z + i * r, X + i * r, Y + i * r, F);
    }

    ifft(Z, 2 * m, r, F);

    for (size_t i = 0; i < m; i++) {
      F.sub(Z[r * i + 0], Z[r * (m + i) + (r - 1)]);
      for (size_t j = 1; j < r; j++) {
        F.add(Z[r * i + j], Z[r * (m + i) + (j - 1)]);
      }
    }
  }

  // Cyclic convolution z=x*y via fft step + cyclic + negacyclic.
  // Destroys x and y, and uses X, Y, Z as workspace
  // for negacyclic().
  static void cyclic_with_workspace(size_t n, Elt z[/*n*/], Elt x[/*n*/],
                                    Elt y[/*n*/], Elt Z[/*n*/], Elt X[/*n*/],
                                    Elt Y[/*n*/], const Field& F) {
    size_t m = n;
    while (m > kKaratsubaSmall) {
      m /= 2;
      for (size_t k = 0; k < m; k++) {
        butterfly(x + k, x + m + k, F);
        butterfly(y + k, y + m + k, F);
      }
      negacyclic_with_workspace(m, z + m, x + m, y + m, Z, X, Y, F);
    }
    basecase_cyclic(m, z, x, y, F);
    while (m < n) {
      for (size_t k = 0; k < m; k++) {
        inverse_butterfly(z + k, z + m + k, F);
      }
      m *= 2;
    }
  }

  static void fft(Elt* X, size_t m, size_t r, const Field& F) {
    for (size_t j = m / 2; j >= 1; j /= 2) {
      for (size_t s = 0; s < m; s += 2 * j) {
        for (size_t t = 0; t < j; t++) {
          size_t shift = (r / j) * t;
          for (size_t l = 0; l < r; ++l) {
            butterfly(&X[r * (s + t) + l], &X[r * (s + t + j) + l], F);
          }
          negate(&X[r * (s + t + j)], shift, F);
          Permutations<Elt>::rotate(&X[r * (s + t + j)], r, shift);
        }
      }
    }
  }

  static void ifft(Elt* X, size_t m, size_t r, const Field& F) {
    Elt scale = F.one();
    for (size_t j = 1; j < m; j *= 2) {
      F.mul(scale, F.half());
      for (size_t s = 0; s < m; s += 2 * j) {
        for (size_t t = 0; t < j; t++) {
          size_t shift = (r / j) * t;
          Permutations<Elt>::unrotate(&X[r * (s + t + j)], r, shift);
          negate(&X[r * (s + t + j)], shift, F);

          for (size_t l = 0; l < r; ++l) {
            butterfly(&X[r * (s + t) + l], &X[r * (s + t + j) + l], F);
          }
        }
      }
    }
    for (size_t i = 0; i < r * m; i++) {
      F.mul(X[i], scale);
    }
  }

  static void lift(Elt* X, const Elt* x, size_t m, size_t r) {
    for (size_t i = 0; i < m; ++i) {
      for (size_t j = 0; j < r; ++j) {
        X[r * i + j] = x[m * j + i];
      }
    }
  }

  static void zerolift(Elt* X, size_t m, size_t r, const Field& F) {
    for (size_t i = 0; i < m; ++i) {
      for (size_t j = 0; j < r; ++j) {
        X[r * (i + m) + j] = F.zero();
      }
    }
  }

  static void unlift(const Elt* X, Elt* x, size_t m, size_t r) {
    for (size_t i = 0; i < m; ++i) {
      for (size_t j = 0; j < r; ++j) {
        x[m * j + i] = X[r * i + j];
      }
    }
  }

  static void basecase_cyclic(size_t n, Elt* z, const Elt* x, const Elt* y,
                              const Field& F) {
    for (size_t k = 0; k < n; ++k) {
      auto s = F.zero();
      for (size_t j = 0; j <= k; ++j) {
        F.add(s, F.mulf(x[j], y[k - j]));
      }
      for (size_t j = k + 1; j < n; ++j) {
        F.add(s, F.mulf(x[j], y[n + k - j]));
      }
      z[k] = s;
    }
  }

  static void basecase_negacyclic(size_t n, Elt* z, const Elt* x, const Elt* y,
                                  const Field& F) {
    for (size_t k = 0; k < n; ++k) {
      auto s = F.zero();
      for (size_t j = 0; j <= k; ++j) {
        F.add(s, F.mulf(x[j], y[k - j]));
      }
      for (size_t j = k + 1; j < n; ++j) {
        F.sub(s, F.mulf(x[j], y[n + k - j]));
      }
      z[k] = s;
    }
  }

  static void basecase_linear(size_t n, Elt z[/*2*n*/], const Elt x[/*n*/],
                              const Elt y[/*n*/], const Field& F) {
    for (size_t k = 0; k < n; ++k) {
      auto s = F.zero();
      for (size_t j = 0; j <= k; ++j) {
        F.add(s, F.mulf(x[j], y[k - j]));
      }
      z[k] = s;
    }
    for (size_t k = n; k < 2 * n; ++k) {
      auto s = F.zero();
      for (size_t j = k - n + 1; j < n; ++j) {
        F.add(s, F.mulf(x[j], y[k - j]));
      }
      z[k] = s;
    }
  }

  // z[k] = sum_j x[n+k-j]*y[j]
  static void basecase_middle(size_t n, Elt z[/*n*/], const Elt x[/*2*n*/],
                              const Elt y[/*n*/], const Field& F) {
    for (size_t k = 0; k < n; ++k) {
      auto s = F.zero();
      for (size_t j = 0; j < n; ++j) {
        F.add(s, F.mulf(x[n + k - j], y[j]));
      }
      z[k] = s;
    }
  }

  static void karatsuba(size_t n, Elt* z, const Elt* x, const Elt* y,
                        const Field& F) {
    if (n <= kKaratsubaSmall) {
      basecase_linear(n, z, x, y, F);
    } else {
      Elt x01[kNussbaumerSmall / 2], y01[kNussbaumerSmall / 2];
      Elt p[kNussbaumerSmall];
      // subtractive karatsuba variant has the advantage that the
      // second half of the algorithm is all additions, so we don't
      // have to think about the signs.
      for (size_t i = 0; i < n / 2; ++i) {
        x01[i] = F.subf(x[i], x[i + n / 2]);
        y01[i] = F.subf(y[i + n / 2], y[i]);
      }
      karatsuba(n / 2, z, x, y, F);
      karatsuba(n / 2, z + n, x + n / 2, y + n / 2, F);
      karatsuba(n / 2, p, x01, y01, F);
      for (size_t i = 0; i < n / 2; ++i) {
        F.add(z[i + n / 2], z[i + n]);
        z[i + n] = z[i + n / 2];
        F.add(z[i + n / 2], p[i]);
        F.add(z[i + n / 2], z[i]);
        F.add(z[i + n], p[i + n / 2]);
        F.add(z[i + n], z[i + n + n / 2]);
      }
    }
  }
  static void karatsuba_negacyclic(size_t n, Elt* z, const Elt* x, const Elt* y,
                                   const Field& F) {
    if (n <= kKaratsubaSmall) {
      basecase_negacyclic(n, z, x, y, F);
    } else {
      Elt x01[kNussbaumerSmall / 2], y01[kNussbaumerSmall / 2];
      Elt p[kNussbaumerSmall], q[kNussbaumerSmall];
      for (size_t i = 0; i < n / 2; ++i) {
        x01[i] = F.subf(x[i], x[i + n / 2]);
        y01[i] = F.subf(y[i + n / 2], y[i]);
      }
      karatsuba(n / 2, z, x, y, F);
      karatsuba(n / 2, q, x + n / 2, y + n / 2, F);
      karatsuba(n / 2, p, x01, y01, F);
      for (size_t i = 0; i < n / 2; ++i) {
        F.add(z[i + n / 2], q[i]);
        F.sub(z[i], q[i + n / 2]);

        // not quite the same as butterfly()
        Elt zi = z[i];
        F.sub(z[i], z[i + n / 2]);
        F.add(z[i + n / 2], zi);

        F.add(z[i + n / 2], p[i]);
        F.sub(z[i], p[i + n / 2]);
      }
    }
  }

  // choose r, m such that r >= m, r*m==n, m as large as
  // possible
  static void choose_radix(size_t* m, size_t* r, size_t n) {
    *m = n;
    *r = 1;
    while (*r < *m) {
      *r *= 2;
      *m /= 2;
    }
  }
};
}  // namespace proofs
#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_NUSSBAUMER_H_
