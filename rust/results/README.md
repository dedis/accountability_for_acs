# Results

`<stack>/<env>/<benchmark>.json` (the revocation stack: CSVs), plots in
`<stack>/plots/`. Local result sets carry an `environment.json` with the
machine, the Docker limits, the git commit and which benchmarks succeeded.

| Env | Source |
|---|---|
| `server`, `mobile` | Recorded with the earlier Node.js harness |
| `sizes` | Recorded proof-size reports (independent of the machine) |
| `local-2cpu` | `tools/benchmark.py`, Docker `--cpus 2 --memory 16g` |
| `local-12cpu` | `tools/benchmark.py`, `--cpus-full 12`: rapidsnark scaling |
| `local-2cpu-pinned` | By hand, `--cpuset-cpus=0,1` (rapidsnark sees 2 cores) |
| `revocation/recorded` | Recorded Node.js runs, including the MP-SPDZ sweep |
| `revocation/local` | Native on the host, no CPU limit |

Plots: `tools/plot.py` (local vs recorded), `tools/plot_revocation_scaling.py`,
`tools/plot_revocation_experiments.py`.

- The zk-friendly keys are set up with `ppot_0080_19.ptau` from the PSE
  Perpetual Powers of Tau (see `third_party.toml`), because the Hermez
  `powersOfTau28_hez_final_19.ptau` mirrors return 403. The circuits and
  timings do not depend on the ptau.
- `--cpus` is a CPU-time quota: rapidsnark still sees every core and is
  throttled, which is why `prove` at 2 CPUs is slower than on the recorded
  server.
