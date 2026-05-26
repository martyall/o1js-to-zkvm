.PHONY: help install build-rust rust-unit-tests rust-e2e-tests rust-e2e-tests-profile prove-cpu prove-cuda lint-check lint dump-simplechain-fixtures clear-simplechain-fixtures dump-treeproofreturn-fixtures clear-treeproofreturn-fixtures dump-nrr-fixtures clear-nrr-fixtures fetch-mainnet-fixture

# Default fixture: the real mainnet blockchain SNARK we fetch via the
# `fetch_blockchain_fixture` OCaml tool. The guest's build.rs reads
# vk.serde.json to bake into verifier.bin; the e2e script reads all four
# files at runtime to assemble the VerifiableProof.
FIXTURE_DIR ?= $(CURDIR)/fixtures/mainnet-blockchain-snark

# Default to the bundled mainnet VK and resolve to an absolute path: cargo
# build scripts run with a different cwd, so a relative VK_JSON fails at
# build time.
VK_JSON ?= $(FIXTURE_DIR)/vk.serde.json
export VK_JSON := $(abspath $(VK_JSON))

# Output directories for the pickles fixtures (overridable). One per recursion
# pattern: NRR (mpv=0), Simple_chain (mpv=1), Tree_proof_return (mpv=2).
NRR_FIXTURE_DIR ?= $(CURDIR)/fixtures/nrr
SIMPLECHAIN_FIXTURE_DIR ?= $(CURDIR)/fixtures/simplechain
TREEPROOFRETURN_FIXTURE_DIR ?= $(CURDIR)/fixtures/treeproofreturn
MAINNET_FIXTURE_DIR ?= $(CURDIR)/fixtures/mainnet-blockchain-snark
# Flake ref for the mina submodule dev shell. We address it as an explicit
# git+file URL with `?submodules=1` so nix pulls mina's nested submodules
# (proof-systems, kimchi-stubs-vendors). The plain `mina#default` relative
# form does NOT include submodules. The `#` is escaped so make doesn't treat
# the rest of the line as a comment.
MINA_DEVSHELL := git+file://$(CURDIR)/mina?submodules=1\#default

.DEFAULT_GOAL := help

help: ## Show this help menu
	@awk 'BEGIN {FS = ":.*?## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install SP1 toolchain and protoc
	./install.sh

build-rust: ## Build the o1zkvm Rust binary (override VK_JSON for a different baked-in VK)
	cargo build --release -p o1-verifier-host

rust-unit-tests: ## Run pickles-verifier's std unit tests over the fixture matrix
	cargo test --release -p pickles-verifier

rust-e2e-tests: ## Run the full Rust+SP1 e2e against $(FIXTURE_DIR) (execute mode, no real proving)
	./scripts/rust-e2e-test.sh

rust-e2e-tests-profile: ## Run e2e under SP1's sampling profiler (Gecko JSON; view at profiler.firefox.com)
	./scripts/rust-e2e-test-profile.sh

prove-cpu: ## Generate a real SP1 proof on the host CPU (rayon-parallel; tune RAYON_NUM_THREADS)
	SP1_PROVER=cpu ./scripts/rust-prove.sh

prove-cuda: ## Generate a real SP1 proof on a local NVIDIA GPU (downloads sp1-gpu-server on first run)
	SP1_PROVER=cuda ./scripts/rust-prove.sh

lint-check: ## Run all linters and formatters in check-only mode
	cargo fmt -p o1-verifier -p o1-verifier-host -p pickles-verifier -- --check
	# Build the host first so the guest ELF exists for include_elf!
	# (clippy skips build scripts, so we need to build separately)
	cargo build --release -p o1-verifier-host
	cargo clippy --workspace --all-targets -- -D warnings
	# no_std variant of the verifier crate (SP1-guest configuration)
	cd crates/pickles-verifier && cargo clippy --no-default-features --all-targets -- -D warnings

lint: ## Run all linters and formatters with auto-fix
	cargo fmt -p o1-verifier -p o1-verifier-host -p pickles-verifier
	cargo build --release -p o1-verifier-host
	cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- -D warnings
	cd crates/pickles-verifier && cargo clippy --no-default-features --all-targets --fix --allow-dirty --allow-staged -- -D warnings

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

fetch-mainnet-fixture: ## Fetch a fresh mainnet blockchain-SNARK fixture (MINA_GRAPHQL_URI required) into $(MAINNET_FIXTURE_DIR)
	@[ -n "$$MINA_GRAPHQL_URI" ] || (echo "error: set MINA_GRAPHQL_URI (e.g. https://api.minascan.io/node/mainnet/v1/graphql)" >&2; exit 1)
	mkdir -p "$(MAINNET_FIXTURE_DIR)"
	nix develop $(MINA_DEVSHELL) -c bash -c 'cd mina && MINA_GRAPHQL_URI="$$MINA_GRAPHQL_URI" dune exec src/app/fetch_blockchain_fixture/fetch_blockchain_fixture.exe -- "$(MAINNET_FIXTURE_DIR)"'
