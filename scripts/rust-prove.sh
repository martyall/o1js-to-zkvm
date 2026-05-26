#!/usr/bin/env bash
set -euo pipefail

# Generate a real SP1 proof of pickles verification end-to-end. Backend
# selected by SP1_PROVER:
#   cpu     - host CPU (rayon-parallel; tune RAYON_NUM_THREADS)
#   cuda    - local NVIDIA GPU via sp1-gpu-server
#   network - Succinct prover network (requires creds)
# Defaults to cpu so machines without a GPU still work.
#
# Inputs come from $FIXTURE_DIR (defaults to fixtures/mainnet-blockchain-snark).
# The fixture's vk.serde.json is also baked into the guest ELF at build time
# — the VK is fixed per ELF.

export SP1_PROVER=${SP1_PROVER:-cpu}
export RUST_LOG=${RUST_LOG:-info}
FIXTURE_DIR=${FIXTURE_DIR:-$(pwd)/fixtures/mainnet-blockchain-snark}
CUDA_DEVICE=${CUDA_DEVICE:-0}
SP1_GPU_SOCKET="/tmp/sp1-cuda-${CUDA_DEVICE}.sock"
SP1_GPU_LOG="/tmp/sp1-gpu-server-${CUDA_DEVICE}.log"
GPU_PID=""

cleanup() {
  if [ -n "$GPU_PID" ] && kill -0 "$GPU_PID" 2>/dev/null; then
    kill "$GPU_PID" 2>/dev/null || true
    wait "$GPU_PID" 2>/dev/null || true
  fi
  rm -f "$SP1_GPU_SOCKET"
}
trap cleanup EXIT

# sp1-cuda 6.0.2's connect retry budget (~1s) is shorter than this GPU's
# socket-bind time (~1.3s), so the SDK's auto-spawned server gets killed off
# before it's ready. Pre-start the server here; the SDK will still try to spawn
# its own and harmlessly fail with EADDRINUSE, then connect to ours.
#
# The script owns the GPU server for its lifetime; any leftover socket from a
# prior run is removed before spawning. If you need to share an externally
# managed server, run prove-cuda from a shell that already has it set up.
ensure_gpu_server() {
  rm -f "$SP1_GPU_SOCKET"
  echo "==> Starting sp1-gpu-server (device $CUDA_DEVICE)..."
  CUDA_VISIBLE_DEVICES="$CUDA_DEVICE" "$HOME/.sp1/bin/sp1-gpu-server" \
    > "$SP1_GPU_LOG" 2>&1 &
  GPU_PID=$!
  for _ in $(seq 1 50); do
    [ -S "$SP1_GPU_SOCKET" ] && break
    if ! kill -0 "$GPU_PID" 2>/dev/null; then
      echo "sp1-gpu-server exited before binding $SP1_GPU_SOCKET; see $SP1_GPU_LOG"
      exit 1
    fi
    sleep 0.1
  done
  if ! [ -S "$SP1_GPU_SOCKET" ]; then
    echo "sp1-gpu-server failed to bind $SP1_GPU_SOCKET within 5s; see $SP1_GPU_LOG"
    exit 1
  fi
  echo "==> sp1-gpu-server ready (PID $GPU_PID)"
}

if [ ! -d "$FIXTURE_DIR" ]; then
  echo "error: FIXTURE_DIR=$FIXTURE_DIR does not exist" >&2
  exit 1
fi

echo "==> Fixture: $FIXTURE_DIR"
echo "==> SP1_PROVER=$SP1_PROVER"

# Build host + guest with VK baked from this fixture.
echo "==> Building o1zkvm..."
VK_JSON="$FIXTURE_DIR/vk.serde.json" make build-rust

if [ "$SP1_PROVER" = "cuda" ]; then
  ensure_gpu_server
fi

echo "==> Generating real SP1 proof ($SP1_PROVER)..."
target/release/o1zkvm --fixture-dir "$FIXTURE_DIR" --prove

echo "==> SP1 proof generation succeeded."
