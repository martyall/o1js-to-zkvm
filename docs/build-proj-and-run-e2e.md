# Build and run

Targets in this doc are exactly what CI runs. If something here drifts from `.github/workflows/ci.yml`, trust the workflow.

## Prerequisites

- Rust — pinned by `rust-toolchain.toml` (1.92.0). `rustup` installs it on first `cargo` invocation.
- `unzip` on `PATH` (used by `install.sh` to extract protoc)

The `lint` and `rust-e2e-test` jobs in CI also install the SP1 toolchain and protoc; see those steps for the exact paths and cache key.

## Install

```
make install
```

Runs `./install.sh`. The script fetches the SP1 toolchain into `$HOME/.sp1`, registers the `succinct` rustup toolchain, and unpacks protoc into `$HOME/.local`. Append both to `PATH`:

```
export PATH="$HOME/.sp1/bin:$HOME/.local/bin:$PATH"
```

CI does the equivalent via the "Add SP1 and protoc to PATH" step.

## Build

```
make build-rust               # o1zkvm host + guest ELF -> target/release/o1zkvm
```

`build-rust` bakes one specific wrap verification key (plus the Pasta SRSes + that VK's wrap Lagrange basis) into the guest at compile time. The VK JSON is selected by `VK_JSON`; the Makefile defaults to `fixtures/mainnet-blockchain-snark/vk.serde.json` and `$(abspath)`s it (cargo build scripts run with a different cwd, so a relative path would fail). Override:

```
VK_JSON=/abs/or/rel/path/vk.serde.json make build-rust
```

The guest blob (`OUT_DIR/verifier.bin`) is ~10 MB: 9 MB of pod-cast Pasta SRSes, ~1 MB of pre-baked Lagrange basis, plus a small postcard-encoded VK. The guest reinterprets the SRSes zero-parse via `bytemuck::cast_slice` and seeds the basis into kimchi's `SRS::lagrange_bases()` cache so `verify` never recomputes it.

## Run

| Target | What it does |
| --- | --- |
| `make rust-unit-tests` | `cargo test -p pickles-verifier`: out-of-circuit verifier over the full fixture matrix (NRR / Simple_chain / Tree_proof_return / mainnet blockchain SNARK), plus encode→decode→verify round-trip. No SP1 emulator. |
| `make rust-e2e-tests` | Build host + guest, then run the SP1 zkVM emulator on the guest ELF against `$FIXTURE_DIR` (default `fixtures/mainnet-blockchain-snark`). Asserts the committed `bool` is `true`. |

Both run in CI. `rust-e2e-tests` is the only one that needs the SP1 toolchain on PATH.

### o1zkvm CLI

```
target/release/o1zkvm --fixture-dir <dir>
```

`<dir>` must contain the four wire files:

- `vk.serde.json` — the kimchi wrap `VerifierIndex` (Rust serde JSON)
- `proof.serde.json` — the kimchi wrap `ProverProof`
- `public_input_skeleton.json` — the pickles `{statement; prev_evals}` skeleton (proof omitted)
- `app_statement.json` — the application's public input(s)

The VK in `<dir>` must match the one the guest was built against (the `VK_JSON` from build time). The host parses the four files, assembles a `VerifiableProof` via `pickles_verifier::wire` + `OcamlProof::into_verifiable`, writes it to the SP1 stdin, and reads the committed `bool`.

Backend is selected by `SP1_PROVER` (`mock` / `cpu` / `cuda` / `network`). Without `--prove` the host runs the SP1 zkVM **executor** (the cycle-counting RISC-V emulator) and `SP1_PROVER` is ignored — there is no real proving. Pass `--prove` to generate a real SP1 proof (`make prove-cpu` and `make prove-cuda` wrap that).

For tracing visibility, set `RUST_LOG`:

```
RUST_LOG=info make rust-e2e-tests
```

## Refresh the mainnet fixture

```
MINA_GRAPHQL_URI=https://api.minascan.io/node/mainnet/v1/graphql \
  make fetch-mainnet-fixture
```

Hits the daemon's GraphQL endpoint, pulls the current `blockchainVerificationKey` + latest block's blockchain SNARK + protocol state hash, and writes the four wire files into `fixtures/mainnet-blockchain-snark`. The VK is fetched from the same node as the proof, so they match — no circuit compilation, profile, or SRS version negotiation is needed.
