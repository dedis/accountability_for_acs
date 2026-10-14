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

#ifndef PRIVACY_PROOFS_ZK_LIB_SUMCHECK_PROVER_H_
#define PRIVACY_PROOFS_ZK_LIB_SUMCHECK_PROVER_H_

#include <stddef.h>

#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/prover_layers.h"
#include "sumcheck/transcript_sumcheck.h"

namespace proofs {

// A high level idea is partially described in chapter 4.6.7 "Leveraging Data
// Parallelism for Further Speedups" in the book "Proofs, Arguments, and
// Zero-Knowledge" by Justin Thaler.
template <class Field>
class Prover : public ProverLayers<Field> {
  using super = ProverLayers<Field>;
  using typename super::bindings;

 public:
  using typename super::inputs;

  explicit Prover(const Field& f) : ProverLayers<Field>(f) {}

  // Generate proof for circuit. pad can be nullptr if the caller does not
  // want to add any pad to the proof. Caller must ensure in, t, and F remain
  // valid during call duration.
  // This method always succeeds, but may not produce a verifying proof if
  // the inputs do not satisfy the circuit.
  void prove(Proof<Field>* proof, const Proof<Field>* pad,
             const Circuit<Field>* circ, const inputs& in, Transcript& t) {
    if (proof == nullptr || circ == nullptr) return;

    TranscriptSumcheck<Field> ts(t, super::f_);
    // The input X is stored at in's layer nl - 1.
    ts.write_input(in.at(circ->nl - 1).get());
    bindings bnd;
    super::prove(proof, pad, circ, in, /*aux=*/nullptr, bnd, ts, super::f_);
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_SUMCHECK_PROVER_H_
