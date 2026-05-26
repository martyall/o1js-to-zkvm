#!/usr/bin/env bash
set -euo pipefail

# Same pipeline as rust-e2e-test.sh, with SP1's sampling profiler enabled.
# Writes a Gecko-format trace to $TRACE_FILE; view at https://profiler.firefox.com/
# (drag the JSON onto the page).
#
# Env vars (all overridable):
#   TRACE_FILE         Output path for the profile (default ./trace.json)
#   TRACE_SAMPLE_RATE  Cycles between samples; widen for big runs (default 100000)
#   FIXTURE_DIR        Pickles wire fixture (default fixtures/mainnet-blockchain-snark)

export TRACE_FILE=${TRACE_FILE:-$(pwd)/trace.json}
export TRACE_SAMPLE_RATE=${TRACE_SAMPLE_RATE:-100000}

echo "==> Profiling enabled"
echo "    TRACE_FILE=$TRACE_FILE"
echo "    TRACE_SAMPLE_RATE=$TRACE_SAMPLE_RATE"

exec ./scripts/rust-e2e-test.sh
