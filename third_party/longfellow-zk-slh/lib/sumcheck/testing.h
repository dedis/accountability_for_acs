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

#ifndef PRIVACY_PROOFS_ZK_LIB_SUMCHECK_TESTING_H_
#define PRIVACY_PROOFS_ZK_LIB_SUMCHECK_TESTING_H_

#include <stddef.h>

#include <cstdint>
#include <memory>

#include "arrays/dense.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/prover.h"
#include "sumcheck/verifier.h"
#include "util/log.h"
#include "util/panic.h"

/*
These are methods that help test modules
by running the prover or the verifier.
*/
namespace proofs {
template <class Field>
void run_prover(const Circuit<Field>* C, std::unique_ptr<Dense<Field>> W,
                Proof<Field>* proof, const Field& F) {
  typename Prover<Field>::inputs pin;

  Prover<Field> prover(F);
  auto V = prover.eval_circuit(&pin, C, std::move(W), F);

  check(V != nullptr, "eval_circuit failed.");

  // Ensure the witness satisfies the circuit before making a proof.
  for (size_t i = 0; i < V->n1_; ++i) {
    if (V->v_[i] != F.zero()) {
      log(INFO, "witness failed: non-zero output at %zu", i);
    }
    check(V->v_[i] == F.zero(), "witness failed, non-zero output");
  }

  Transcript tsp((uint8_t*)"testing", 7);
  prover.prove(proof, nullptr, C, pin, tsp);
}

template <class Field>
void run_verifier(const Circuit<Field>* C, std::unique_ptr<Dense<Field>> W,
                  Proof<Field>& proof, const Field& F) {
  const char* why = "ok";
  auto V = std::make_unique<Dense<Field>>(F);
  Transcript tsv((uint8_t*)"testing", 7);
  check(Verifier<Field>::verify(&why, C, &proof, std::move(W), tsv, F), why);
}
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_SUMCHECK_TESTING_H_
