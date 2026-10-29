"""Lattice-estimator check of the Module-LWE parameters of the CFT encryption
(crates/pqc/src/lwe.rs, third_party/longfellow-zk/lib/circuits/tests/pq/
credential/lwe.h).

Usage: python -I tools/lwe_estimate.py <lattice-estimator checkout>

Needs SageMath (or passagemath-standard) and a checkout of
https://github.com/malb/lattice-estimator. Runs every attack of
LWE.estimate except Arora-GB and coded BKW (both far above the others for
these parameters) with the default cost models.

Two Module-LWE instances per category, over R_q = Z_q[X]/(X^256 + 1),
q = 8380417, secrets and errors uniform in [-eta, eta]:

- key share: each authority publishes t_i = A s_i + e_i (K x K matrix, one
  instance per key slot); the sum of the shares is no easier to find.
- ciphertext: U = A^T R + E1 and the K-dimensional rows of T in V give
  K + 3 samples of R.

The check passes when the cheapest attack on each instance costs at least as
much as on the Module-LWE instance of the ML-DSA parameter set of the same
category (ML-DSA-65: K = 5, k = 6, eta = 4; ML-DSA-87: K = 7, k = 8,
eta = 2), and ML-KEM is printed for comparison. Exits 1 if a check fails.
"""

import math
import sys

sys.path.insert(0, sys.argv[1])

from estimator import LWE, nd, schemes  # noqa: E402
from estimator.lwe_parameters import LWEParameters  # noqa: E402

Q = 8380417
N = 256
# category: (K, eta, rows of the ML-DSA matrix, ML-DSA, ML-KEM)
CATEGORIES = {
    3: (5, 4, 6, "ML-DSA-65", schemes.Kyber768),
    5: (7, 2, 8, "ML-DSA-87", schemes.Kyber1024),
}


def instance(tag, k, rows, eta):
    small = nd.Uniform(-eta, eta)
    return LWEParameters(n=k * N, q=Q, Xs=small, Xe=small, m=rows * N, tag=tag)


def cheapest(params):
    """log2 of the cost of the cheapest attack, and its name."""
    res = LWE.estimate(params, deny_list=("arora-gb", "bkw"), quiet=True)
    name, cost = min(res.items(), key=lambda kv: kv[1]["rop"])
    return math.log2(cost["rop"]), name


def main():
    failed = False
    for category, (k, eta, rows, ml_dsa, ml_kem) in CATEGORIES.items():
        bits, attack = cheapest(instance(ml_dsa, k, rows, eta))
        kem_bits, kem_attack = cheapest(ml_kem)
        print(f"category {category}: {ml_dsa} 2^{bits:.1f} ({attack}), "
              f"{ml_kem.tag} 2^{kem_bits:.1f} ({kem_attack})")
        for name, rows_ours in (("key share", k), ("ciphertext", k + 3)):
            ours, how = cheapest(instance(name, k, rows_ours, eta))
            ok = ours >= bits
            failed |= not ok
            print(f"  {name:10s} n={k * N} m={rows_ours * N} eta={eta}: "
                  f"2^{ours:.1f} ({how}) {'ok' if ok else 'BELOW ' + ml_dsa}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
