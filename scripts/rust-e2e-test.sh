#!/usr/bin/env bash
set -euo pipefail

# End-to-end: build the o1zkvm host (the guest sub-build bakes the wrap VK +
# SRSes + Lagrange basis into verifier.bin from $FIXTURE_DIR/vk.serde.json),
# then run the guest inside the SP1 zkVM emulator against the fixture's proof
# + public input + app statement. The guest commits a bool; we assert it's
# true.
#
# Defaults to the real mainnet Mina blockchain SNARK fixture (fetched by
# mina/src/app/fetch_blockchain_fixture). Override FIXTURE_DIR to point at any
# other dumped pickles wire (vk.serde.json + proof.serde.json +
# public_input_skeleton.json + app_statement.json), but rebuild after — the
# VK is fixed per ELF.

FIXTURE_DIR=${FIXTURE_DIR:-$(pwd)/fixtures/mainnet-blockchain-snark}

if [ ! -d "$FIXTURE_DIR" ]; then
  echo "error: FIXTURE_DIR=$FIXTURE_DIR does not exist" >&2
  exit 1
fi

for f in vk.serde.json proof.serde.json public_input_skeleton.json app_statement.json; do
  if [ ! -f "$FIXTURE_DIR/$f" ]; then
    echo "error: missing $FIXTURE_DIR/$f" >&2
    exit 1
  fi
done

echo "==> Fixture: $FIXTURE_DIR"

# Build host + guest. The guest's build.rs reads VK_JSON, computes the wrap
# Lagrange basis at the VK's domain, pod-encodes everything into
# OUT_DIR/verifier.bin, and the guest include_bytes!'s it.
echo "==> Building o1zkvm (host + guest, VK baked from vk.serde.json)..."
VK_JSON="$FIXTURE_DIR/vk.serde.json" make build-rust

# Execute mode: the SP1 zkVM emulator runs the guest ELF, no real proving.
# The guest reads a VerifiableProof from stdin, runs pickles_verifier::verify,
# and commits a bool. The host asserts that bool is true.
echo "==> Verifying inside SP1 zkVM (execute mode)..."
target/release/o1zkvm --fixture-dir "$FIXTURE_DIR"

echo "==> All e2e tests passed!"
