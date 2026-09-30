# Running the MPC benchmark on SPHERE

How to run the MP-SPDZ revocation sweep (`revocation_pet_mpc`, driven by
`mpc/run_sweep.sh`) on the [SPHERE testbed](https://launch.sphere-testbed.net).

`revocation_pet_mpc` starts all three MP-SPDZ parties (`shamir-party.x`) on the
machine it runs on, so they communicate over localhost. One node is enough;
see the last section for running the parties on separate nodes.

SPHERE runs on MergeTB: you describe the machines in a small Python model,
reserve them ("realize"), start them ("materialize"), and reach them through an
experiment development container (XDC). Nodes reach the internet through the
testbed gateway, so `apt`, `rustup` and `git` work on them
([experimentation docs](https://mergetb.gitlab.io/testbeds/sphere/sphere-docs/docs/experimentation/)).

## 1. Account and CLI

Sign in at <https://launch.sphere-testbed.net>, join or create a project, and
add your SSH public key. Install the `mrg` CLI, then `mrg login <username>`
([CLI reference](https://mergetb.org/docs/experimentation/cli-reference/)).

## 2. Model: `model.py`

```python
from mergexp import *

net = Network('mpc-bench')
net.node('bench', image == 'ubuntu2204', proc.cores >= 8, memory.capacity >= gb(16))
experiment(net)
```

Syntax: [model reference](https://mergetb.gitlab.io/testbeds/sphere/sphere-docs/docs/experimentation/model-ref/).
Without `image`, the node runs Debian `bullseye`; Ubuntu 22.04 is requested
instead. 8 cores and 16 GB match the server profile of the recorded runs.

## 3. Experiment and XDC

```bash
mrg new experiment mpc.<project> 'MPC revocation sweep'
mrg push ./model.py mpc.<project>
mrg realize run.mpc.<project> revision <revision printed by push>
mrg mat run.mpc.<project>
mrg new xdc x0.<project>
mrg xdc attach x0.<project> run.mpc.<project>
```

([Hello World](https://mergetb.gitlab.io/testbeds/sphere/sphere-docs/docs/experimentation/hello-world/),
[XDCs](https://mergetb.gitlab.io/testbeds/sphere/sphere-docs/docs/experimentation/xdc/))

Add to `~/.ssh/config`:

```
Host mergejump
    Hostname jump.sphere-testbed.net
    Port 2022
    User <username>
    IdentityFile ~/.ssh/merge_key
```

`ssh -J mergejump x0-<project>` reaches the XDC (the SSH name uses a dash, not
a dot). From the XDC, `ssh bench` reaches the node.

## 4. Copy the code

From the repository root on your machine (or commit, push and `git clone` on
the node instead):

```bash
rsync -a --exclude target --exclude .work --exclude .git \
  -e "ssh -J mergejump,x0-<project>" ./ bench:~/acs/
```

## 5. Install the tools on the node

```bash
sudo apt-get update && sudo apt-get install -y build-essential python3 git \
  libboost-dev libsodium-dev libssl-dev libgmp-dev libntl-dev yasm tmux
curl -sSf https://sh.rustup.rs | sh -s -- -y && . ~/.cargo/env

# MP-SPDZ v0.4.2, the version of the recorded runs
git clone --branch v0.4.2 --recursive https://github.com/data61/MP-SPDZ.git ~/mp-spdz
cd ~/mp-spdz && make -j8 shamir-party.x && Scripts/setup-ssl.sh 3
```

`Scripts/setup-ssl.sh 3` creates the TLS keys of the three parties. The
MP-SPDZ release tarball may contain a prebuilt Linux `shamir-party.x`, which
would skip `make`; this has not been checked. These steps have not been tested
on SPHERE yet.

## 6. Run the sweep

Run inside `tmux`: the full sweep takes hours, and an SSH drop would stop it.

```bash
tmux new -s mpc
cd ~/acs && cargo build --release -p revocation
MP_SPDZ_PATH=~/mp-spdz NUMS="10 20 50 100 200 500 1000" ITERATIONS=10 TAU=2 \
  bash crates/revocation/mpc/run_sweep.sh
python3 crates/revocation/mpc/summarize.py .work/revocation/mpc-sweep_*/results.csv \
  results/revocation/sphere
```

For a first check, use `NUMS="10 20" ITERATIONS=1`.

## 7. Copy the results back and release the node

```bash
rsync -a -e "ssh -J mergejump,x0-<project>" bench:~/acs/results/revocation/sphere/ \
  results/revocation/sphere/
mrg relinquish run.mpc.<project>
```

Releasing the reservation frees the machine for other users.

## Parties on separate nodes

Measuring real network traffic between the parties needs a code change, not
made yet:

1. Add a `--hosts` option to `revocation_pet_mpc`.
2. Pass party 0's address to every party with MP-SPDZ's `-h` option, and start
   each party on its own node (`p0`, `p1`, `p2` in the model).
3. Link the nodes in the model, where bandwidth and latency can be set:
   `net.connect([p0, p1, p2], capacity == mbps(1000), latency == ms(10))`.
