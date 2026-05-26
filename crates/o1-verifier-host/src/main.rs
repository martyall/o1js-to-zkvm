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
//! it to the guest stdin, and runs the SP1 zkVM (execute or prove).
//!
//! The guest ELF has a wrap VK baked in at build time via `VK_JSON` (see
//! `o1-verifier/build.rs`). The fixture passed here MUST be against that
//! same VK — there is no runtime mismatch check yet.

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use pickles_verifier::wire::{parse_app_statement, parse_wrap_proof, parse_wrap_vk, OcamlProof};
use sp1_sdk::{include_elf, Elf, Prover, ProverClient, ProvingKey, SP1Stdin};

const ELF: Elf = include_elf!("o1-verifier");

#[derive(Parser)]
#[command(name = "o1-verifier-host")]
#[command(about = "Run the o1-verifier guest program (pickles verification) in the SP1 zkVM")]
struct Cli {
    /// Path to a fixture directory containing vk.serde.json, proof.serde.json,
    /// public_input_skeleton.json, and app_statement.json. The VK must match
    /// the one the guest was built against (see o1-verifier's VK_JSON env var).
    #[arg(short, long)]
    fixture_dir: PathBuf,

    /// Generate a real SP1 proof instead of just executing the program.
    /// Backend is selected by the SP1_PROVER env var (cpu, cuda, network).
    #[arg(long)]
    prove: bool,
}

#[tokio::main]
async fn main() {
    // Pick up SP1's tracing logs. Default filter is "off" unless RUST_LOG is
    // set, so set `RUST_LOG=info` (or higher) to see proving progress.
    sp1_sdk::utils::setup_logger();

    let cli = Cli::parse();

    // Load the four wire files.
    let read = |name: &str| {
        let p = cli.fixture_dir.join(name);
        fs::read_to_string(&p).unwrap_or_else(|e| panic!("failed to read {}: {e}", p.display()))
    };
    let vk_json = read("vk.serde.json");
    let proof_json = read("proof.serde.json");
    let skeleton_json = read("public_input_skeleton.json");
    let app_stmt_json = read("app_statement.json");

    // Parse + assemble the VerifiableProof host-side.
    let wrap_vk = parse_wrap_vk(&vk_json).expect("parse vk.serde.json");
    let wrap_proof = parse_wrap_proof(&proof_json).expect("parse proof.serde.json");
    let ocaml = OcamlProof::parse(&skeleton_json).expect("parse public_input_skeleton.json");
    let app_stmt = parse_app_statement(&app_stmt_json).expect("parse app_statement.json");

    let verifiable = ocaml
        .into_verifiable(wrap_proof, &wrap_vk, &[app_stmt])
        .expect("OcamlProof::into_verifiable");

    let mut stdin = SP1Stdin::new();
    stdin.write(&verifiable);

    // Prover backend is selected by SP1_PROVER env var (mock, cpu, cuda,
    // network). Defaults to cpu.
    let client = ProverClient::from_env().await;

    if cli.prove {
        let pk = client.setup(ELF).await.expect("setup failed");
        let proof = client.prove(&pk, stdin).await.expect("prove failed");

        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("proof verification failed");

        let mut public_values = proof.public_values.clone();
        let valid: bool = public_values.read();
        assert!(valid, "Pickles proof verification failed inside SP1 zkVM");

        println!("Pickles proof verified successfully inside SP1 zkVM!");
        println!("SP1 proof generated and verified.");
    } else {
        let (mut public_values, report) =
            client.execute(ELF, stdin).await.expect("execution failed");

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
}
