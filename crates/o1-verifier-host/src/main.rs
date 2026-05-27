//! Host driver for the `o1-verifier` SP1 guest.
//!
//! Takes a fixture directory containing the OCaml-dumped pickles wire files —
//! ```
//!   <fixture_dir>/
//!     vk.serde.json
//!     proof.serde.json
//!     public_input_skeleton.json
//!     app_statement.json
//! ```
//! — assembles a [`pickles_verifier::types::VerifiableProof`] host-side (via
//! `pickles_verifier::wire` parsers + `OcamlProof::into_verifiable`), writes
//! it to the guest stdin, and runs the SP1 zkVM in the mode chosen on the
//! command line.
//!
//! The guest ELF has a wrap VK baked in at build time via `VK_JSON` (see
//! `o1-verifier/build.rs`). The fixture passed here MUST be against that
//! same VK — there is no runtime mismatch check yet.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use pickles_verifier::types::VerifiableProof;
use pickles_verifier::wire::{parse_app_statement, parse_wrap_proof, parse_wrap_vk, OcamlProof};
use sp1_sdk::network::{get_explorer_url_for_mode, B256};
use sp1_sdk::{include_elf, Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};

const ELF: Elf = include_elf!("o1-verifier");

#[derive(Parser)]
#[command(name = "o1zkvm")]
#[command(about = "Run the o1-verifier guest program (pickles verification) in the SP1 zkVM")]
struct Cli {
    /// Path to a fixture directory containing vk.serde.json, proof.serde.json,
    /// public_input_skeleton.json, and app_statement.json. The VK must match
    /// the one the guest was built against (see o1-verifier's VK_JSON env var).
    #[arg(short, long, global = true)]
    fixture_dir: Option<PathBuf>,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Execute the guest in the SP1 zkVM emulator (no real proof; prints cycle stats)
    Execute,
    /// Generate a real SP1 proof on the host CPU
    Cpu,
    /// Generate a real SP1 proof on the local NVIDIA GPU (sp1-gpu-server)
    Cuda,
    /// Submit a real SP1 proof request to Succinct's prover network
    Network(NetworkArgs),
}

#[derive(Args)]
struct NetworkArgs {
    /// Secp256k1 / Ethereum-format private key used to sign network requests.
    /// Read from $NETWORK_PRIVATE_KEY if not passed on the command line.
    #[arg(long, env = "NETWORK_PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// Override the network RPC URL. Default depends on --hosted:
    /// mainnet -> rpc.mainnet.succinct.xyz; hosted -> rpc.production.succinct.xyz.
    #[arg(long, env = "NETWORK_RPC_URL")]
    rpc_url: Option<String>,

    /// Use Succinct's hosted/reserved-capacity network mode (skips local
    /// simulation by default and uses maximum cycle/gas limits). Requires
    /// reserved capacity provisioned to the signing key's account.
    #[arg(long)]
    hosted: bool,

    /// Per-request fulfillment strategy. Only relevant on the mainnet/auction
    /// network; `hosted` and `reserved` route the request to those provers.
    #[arg(long, value_enum, default_value_t = Strategy::Auction)]
    strategy: Strategy,

    /// Maximum cycles the network should run before failing the request.
    #[arg(long)]
    cycle_limit: Option<u64>,

    /// Maximum proof-gas units (default depends on network mode).
    #[arg(long)]
    gas_limit: Option<u64>,

    /// Maximum price per proof-gas unit in PROVE wei (auction strategy only).
    #[arg(long)]
    max_price_per_pgu: Option<u64>,

    /// Wall-clock timeout for the whole proof request, in seconds.
    #[arg(long)]
    timeout_secs: Option<u64>,

    /// Skip local execution simulation before submitting the request. Faster
    /// to dispatch, but you only find out about guest panics from the network.
    #[arg(long)]
    skip_simulation: bool,

    /// Proof artifact the network should produce. The Succinct prover network
    /// rejects `core`; defaults to `compressed` (recursive STARK, smallest +
    /// cheapest network artifact). Use `groth16`/`plonk` for an on-chain-
    /// verifier-friendly SNARK wrapper.
    #[arg(long, value_enum, env = "NETWORK_PROOF_MODE", default_value_t = ProofMode::Compressed)]
    proof_mode: ProofMode,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Strategy {
    Auction,
    Hosted,
    Reserved,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ProofMode {
    Compressed,
    Groth16,
    Plonk,
}

impl From<ProofMode> for sp1_sdk::SP1ProofMode {
    fn from(m: ProofMode) -> Self {
        use sp1_sdk::SP1ProofMode as P;
        match m {
            ProofMode::Compressed => P::Compressed,
            ProofMode::Groth16 => P::Groth16,
            ProofMode::Plonk => P::Plonk,
        }
    }
}

impl From<Strategy> for sp1_sdk::network::FulfillmentStrategy {
    fn from(s: Strategy) -> Self {
        use sp1_sdk::network::FulfillmentStrategy as F;
        match s {
            Strategy::Auction => F::Auction,
            Strategy::Hosted => F::Hosted,
            Strategy::Reserved => F::Reserved,
        }
    }
}

fn load_verifiable(fixture_dir: &Path) -> VerifiableProof {
    let read = |name: &str| {
        let p = fixture_dir.join(name);
        fs::read_to_string(&p).unwrap_or_else(|e| panic!("failed to read {}: {e}", p.display()))
    };
    let vk_json = read("vk.serde.json");
    let proof_json = read("proof.serde.json");
    let skeleton_json = read("public_input_skeleton.json");
    let app_stmt_json = read("app_statement.json");

    let wrap_vk = parse_wrap_vk(&vk_json).expect("parse vk.serde.json");
    let wrap_proof = parse_wrap_proof(&proof_json).expect("parse proof.serde.json");
    let ocaml = OcamlProof::parse(&skeleton_json).expect("parse public_input_skeleton.json");
    let app_stmt = parse_app_statement(&app_stmt_json).expect("parse app_statement.json");

    ocaml
        .into_verifiable(wrap_proof, &wrap_vk, &[app_stmt])
        .expect("OcamlProof::into_verifiable")
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let cli = Cli::parse();

    let fixture_dir = cli.fixture_dir.as_ref().expect("missing --fixture-dir");

    let verifiable = load_verifiable(fixture_dir);
    let mut stdin = SP1Stdin::new();
    stdin.write(&verifiable);

    match cli.mode {
        Mode::Execute => run_execute(stdin).await,
        Mode::Cpu => run_cpu(stdin).await,
        Mode::Cuda => run_cuda(stdin).await,
        Mode::Network(args) => run_network(stdin, args).await,
    }
}

async fn run_execute(stdin: SP1Stdin) {
    let client = ProverClient::builder().cpu().build().await;
    let (mut public_values, report) = client.execute(ELF, stdin).await.expect("execution failed");

    let valid: bool = public_values.read();
    assert!(valid, "Pickles proof verification failed inside SP1 zkVM");

    println!("Pickles proof verified successfully inside SP1 zkVM!");
    println!("Execution used {} cycles", report.total_instruction_count());

    let mut entries: Vec<(&String, &u64)> = report.cycle_tracker.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (name, cycles) in entries {
        println!("  {name}: {cycles} cycles");
    }
}

async fn run_cpu(stdin: SP1Stdin) {
    let client = ProverClient::builder().cpu().build().await;
    let pk = client.setup(ELF).await.expect("setup failed");
    let proof = client.prove(&pk, stdin).await.expect("prove failed");
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("proof verification failed");
    report_proof(proof);
}

async fn run_cuda(stdin: SP1Stdin) {
    let client = ProverClient::builder().cuda().build().await;
    let pk = client.setup(ELF).await.expect("setup failed");
    let proof = client.prove(&pk, stdin).await.expect("prove failed");
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("proof verification failed");
    report_proof(proof);
}

async fn run_network(stdin: SP1Stdin, args: NetworkArgs) {
    let mut builder = ProverClient::builder()
        .network()
        .private_key(&args.private_key);
    if let Some(url) = args.rpc_url.as_deref() {
        builder = builder.rpc_url(url);
    }
    if args.hosted {
        builder = builder.hosted();
    }
    let client = builder.build().await;

    let pk = client.setup(ELF).await.expect("setup failed");

    let timeout = args.timeout_secs.map(Duration::from_secs);

    let mut req = client
        .prove(&pk, stdin)
        .mode(args.proof_mode.into())
        .strategy(args.strategy.into());
    if args.skip_simulation {
        req = req.skip_simulation(true);
    }
    if let Some(c) = args.cycle_limit {
        req = req.cycle_limit(c);
    }
    if let Some(g) = args.gas_limit {
        req = req.gas_limit(g);
    }
    if let Some(p) = args.max_price_per_pgu {
        req = req.max_price_per_pgu(p);
    }
    if let Some(t) = timeout {
        req = req.timeout(t);
    }

    // Submit the request first (returns the request id without waiting for
    // fulfillment), print a locator the operator can copy into the explorer,
    // then wait for the proof. This split mirrors what sp1-sdk's tracing
    // emits internally but routes the locator to stdout so it survives even
    // when RUST_LOG filtering hides info-level tracing.
    let request_id: B256 = req.request().await.expect("network request submit failed");
    print_request_locator(&client, request_id);

    let proof = client
        .wait_proof(request_id, timeout, None)
        .await
        .expect("network prove failed");
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("proof verification failed");
    report_proof_with_request(proof, request_id);
}

fn print_request_locator(client: &sp1_sdk::NetworkProver, request_id: B256) {
    let explorer = get_explorer_url_for_mode(client.network_mode());
    println!();
    println!("==> Proof request submitted");
    println!("    request_id: {request_id}");
    println!(
        "    explorer:   {}/request/{}",
        explorer.trim_end_matches('/'),
        request_id
    );
    println!("    (look up by request_id if the URL pattern changes)");
    println!();
}

fn report_proof(proof: sp1_sdk::SP1ProofWithPublicValues) {
    let mut public_values = proof.public_values.clone();
    let valid: bool = public_values.read();
    assert!(valid, "Pickles proof verification failed inside SP1 zkVM");

    println!("Pickles proof verified successfully inside SP1 zkVM!");
    println!("SP1 proof generated and verified.");
}

fn report_proof_with_request(proof: sp1_sdk::SP1ProofWithPublicValues, request_id: B256) {
    let mut public_values = proof.public_values.clone();
    let valid: bool = public_values.read();
    assert!(valid, "Pickles proof verification failed inside SP1 zkVM");

    println!("Pickles proof verified successfully inside SP1 zkVM!");
    println!("SP1 proof generated and verified. request_id: {request_id}");
}
