# o1js-to-zkvm

Verify a pickles proof (Mina blockchain SNARK or any compatible kimchi-wrap
recursive proof) inside the SP1 zkVM. Bridges Mina-shaped recursive proofs
into the broader SP1 / zkVM ecosystem so they can be composed with other
SP1 programs.

## Layout

- `crates/pickles-verifier` — out-of-circuit pickles verifier (kimchi wrap
  + stage-1 deferred + stage-2 accumulator). Builds in both `std` and
  `no_std`; the guest uses `no_std`.
- `crates/o1-verifier` — SP1 guest. `build.rs` reads `$VK_JSON` and bakes
  the wrap verification key + Pasta SRSes + wrap Lagrange basis into
  `verifier.bin`. `main.rs` reads a `VerifiableProof` from stdin and
  commits a `bool`.
- `crates/o1-verifier-host` — host driver (`o1zkvm` binary). Reads a
  fixture directory, builds a `VerifiableProof`, ships it to the guest.
- `fixtures/mainnet-blockchain-snark` — a real mainnet Mina blockchain
  SNARK fixture (vk + proof + skeleton + statement). Fetched via the
  `fetch_blockchain_fixture` OCaml tool in `mina/src/app`.

## Install

```sh
make install
```

Installs the SP1 toolchain (v6.0.2) and protoc.

## Build

```sh
make build-rust
```

Defaults to the bundled mainnet fixture's VK. Override `VK_JSON` to bake a
different VK into the guest ELF (`VK_JSON=/path/to/vk.serde.json make
build-rust`).

## End-to-end test

```sh
make rust-e2e-tests
```

Builds the host (which triggers the guest sub-build), then runs the SP1
zkVM emulator on the guest ELF against `fixtures/mainnet-blockchain-snark`.
The guest commits `true` on success. Set `FIXTURE_DIR` to point at a
different pickles wire fixture (must match the baked-in VK — rebuild after
overriding `VK_JSON`).

## Unit tests

```sh
make rust-unit-tests
```

Runs `pickles-verifier`'s native test suite over the full fixture matrix
(NRR / Simple_chain / Tree_proof_return / mainnet). No SP1 emulator.

## Real proof generation

```sh
make prove-cpu        # rayon-parallel CPU prover
make prove-cuda       # local NVIDIA GPU via sp1-gpu-server
```

## Refresh the mainnet fixture

```sh
MINA_GRAPHQL_URI=https://api.minascan.io/node/mainnet/v1/graphql \
  make fetch-mainnet-fixture
```
