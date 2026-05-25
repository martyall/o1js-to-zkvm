.PHONY: help install deps build-ts build-rust ts-unit-tests rust-unit-tests ts-e2e-tests rust-e2e-tests rust-e2e-tests-profile prove-cpu prove-cuda lint-check lint dump-simplechain-fixtures clear-simplechain-fixtures dump-treeproofreturn-fixtures clear-treeproofreturn-fixtures dump-nrr-fixtures clear-nrr-fixtures

CIRCUIT_FIXTURE := $(CURDIR)/fixtures/circuit.json

# Default to the bundled fixture and resolve to an absolute path: cargo build
# scripts run with a different cwd, so a relative CIRCUIT_JSON fails at build time.
CIRCUIT_JSON ?= $(CIRCUIT_FIXTURE)
export CIRCUIT_JSON := $(abspath $(CIRCUIT_JSON))

# Output directories for the pickles fixtures (overridable). One per recursion
# pattern: NRR (mpv=0), Simple_chain (mpv=1), Tree_proof_return (mpv=2).
NRR_FIXTURE_DIR ?= $(CURDIR)/fixtures/nrr
SIMPLECHAIN_FIXTURE_DIR ?= $(CURDIR)/fixtures/simplechain
TREEPROOFRETURN_FIXTURE_DIR ?= $(CURDIR)/fixtures/treeproofreturn
# Flake ref for the mina submodule dev shell. We address it as an explicit
# git+file URL with `?submodules=1` so nix pulls mina's nested submodules
# (proof-systems, kimchi-stubs-vendors). The plain `mina#default` relative
# form does NOT include submodules. The `#` is escaped so make doesn't treat
# the rest of the line as a comment.
MINA_DEVSHELL := git+file://$(CURDIR)/mina?submodules=1\#default

.DEFAULT_GOAL := help

help: ## Show this help menu
	@awk 'BEGIN {FS = ":.*?## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: deps ## Install SP1 toolchain, protoc, and npm dependencies
	./install.sh

deps: ## Install npm dependencies
	npm ci

build-ts: ## Build the TypeScript CLI (run as `npx o1js-cli ...`)
	npm run build
	chmod +x dist/src/cli.js

build-rust: ## Build the o1zkvm Rust binary (override CIRCUIT_JSON to use a custom circuit)
	cargo build --release -p o1-verifier-host

ts-unit-tests: build-ts ## Run TypeScript unit tests
	npm test

rust-unit-tests: ## Run native Rust unit and integration tests against the checked-in fixtures
	cargo test --release -p o1-verifier-lib --features std

ts-e2e-tests: build-ts ## Run the TypeScript CLI end-to-end script
	./scripts/ts-e2e-test.sh

rust-e2e-tests: ## Run the full Rust+SP1 end-to-end script (mock prover, no GPU)
	./scripts/rust-e2e-test.sh

rust-e2e-tests-profile: ## Run e2e under SP1's sampling profiler (Gecko JSON; view at profiler.firefox.com)
	./scripts/rust-e2e-test-profile.sh

prove-cpu: ## Generate a real SP1 proof on the host CPU (rayon-parallel; tune RAYON_NUM_THREADS)
	SP1_PROVER=cpu ./scripts/rust-prove.sh

prove-cuda: ## Generate a real SP1 proof on a local NVIDIA GPU (downloads sp1-gpu-server on first run)
	SP1_PROVER=cuda ./scripts/rust-prove.sh

lint-check: ## Run all linters and formatters in check-only mode
	npm run format:check
	npm run lint
	cargo fmt -p o1-verifier -p o1-verifier-host -p o1-verifier-lib -- --check
	# Build the host first so the guest ELF exists for include_elf!
	# (clippy skips build scripts, so we need to build separately)
	cargo build --release -p o1-verifier-host
	cargo clippy --all-targets --features std -- -D warnings

lint: ## Run all linters and formatters with auto-fix
	npm run format
	npm run lint
	cargo fmt -p o1-verifier -p o1-verifier-host -p o1-verifier-lib
	cargo build --release -p o1-verifier-host
	cargo clippy --all-targets --features std --fix --allow-dirty --allow-staged -- -D warnings

dump-simplechain-fixtures: ## Dump Simple_chain wrap-proof fixtures (b0,b1,b2) to $(SIMPLECHAIN_FIXTURE_DIR)
	mkdir -p "$(SIMPLECHAIN_FIXTURE_DIR)/wrap0" "$(SIMPLECHAIN_FIXTURE_DIR)/wrap1" "$(SIMPLECHAIN_FIXTURE_DIR)/wrap2"
	nix develop $(MINA_DEVSHELL) -c bash -c 'cd mina && KIMCHI_DETERMINISTIC_SEED=42 dune exec src/lib/crypto/pickles/dump_simple_chain_fixtures/dump_simple_chain_fixtures.exe -- "$(SIMPLECHAIN_FIXTURE_DIR)"'

clear-simplechain-fixtures: ## Remove the Simple_chain fixture directory ($(SIMPLECHAIN_FIXTURE_DIR))
	rm -rf "$(SIMPLECHAIN_FIXTURE_DIR)"

dump-treeproofreturn-fixtures: ## Dump Tree_proof_return wrap-proof fixtures (mpv=2, b0,b1,b2) to $(TREEPROOFRETURN_FIXTURE_DIR)
	mkdir -p "$(TREEPROOFRETURN_FIXTURE_DIR)/wrap0" "$(TREEPROOFRETURN_FIXTURE_DIR)/wrap1" "$(TREEPROOFRETURN_FIXTURE_DIR)/wrap2"
	nix develop $(MINA_DEVSHELL) -c bash -c 'cd mina && KIMCHI_DETERMINISTIC_SEED=42 dune exec src/lib/crypto/pickles/dump_tree_proof_return_fixtures/dump_tree_proof_return_fixtures.exe -- "$(TREEPROOFRETURN_FIXTURE_DIR)"'

clear-treeproofreturn-fixtures: ## Remove the Tree_proof_return fixture directory ($(TREEPROOFRETURN_FIXTURE_DIR))
	rm -rf "$(TREEPROOFRETURN_FIXTURE_DIR)"

dump-nrr-fixtures: ## Dump No_recursion_return wrap-proof fixture (mpv=0) to $(NRR_FIXTURE_DIR)
	mkdir -p "$(NRR_FIXTURE_DIR)"
	nix develop $(MINA_DEVSHELL) -c bash -c 'cd mina && KIMCHI_DETERMINISTIC_SEED=42 dune exec src/lib/crypto/pickles/dump_nrr_fixtures/dump_nrr_fixtures.exe -- "$(NRR_FIXTURE_DIR)"'

clear-nrr-fixtures: ## Remove the No_recursion_return fixture directory ($(NRR_FIXTURE_DIR))
	rm -rf "$(NRR_FIXTURE_DIR)"
