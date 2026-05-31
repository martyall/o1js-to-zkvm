//! Fetch a Mina blockchain SNARK fixture directly from a daemon's GraphQL
//! endpoint, in a form a Rust caller can consume without an OCaml runtime.
//!
//! Writes three files to `--out`:
//!   * `proof.bin_prot` — raw bin_prot bytes of the protocol state proof
//!     (base64-decoded from `bestChain[0].protocolStateProof.base64`).
//!     This is structurally the same as `MinaBaseProofStableV2` carried
//!     in `mina_p2p_messages`.
//!   * `vk.json` — the daemon's `blockchainVerificationKey`, kimchi
//!     Rust-serde JSON shape (the form `pickles_verifier::wire::parse_wrap_vk`
//!     expects).
//!   * `state_hash.txt` — the decimal `stateHashField` (Tick field element).
//!
//! Default endpoint is mesa MUT; switch with `--network`.
//!
//! No schema codegen — the query is small enough to hand-write and the
//! response is parsed via `serde_json::Value`.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use clap::{Parser, ValueEnum};
use serde_json::{json, Value};

const QUERY: &str = r#"
{
  blockchainVerificationKey
  bestChain(maxLength: 1) {
    stateHashField
    protocolStateProof { base64 }
  }
}
"#;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Network {
    MesaMut,
    Mainnet,
}

impl Network {
    fn endpoint(self) -> &'static str {
        match self {
            Network::MesaMut => "https://plain-1-graphql.mesa-mut.minaprotocol.com/graphql",
            Network::Mainnet => "https://api.minascan.io/node/mainnet/v1/graphql",
        }
    }
}

#[derive(Parser)]
#[command(about = "Fetch a Mina blockchain SNARK fixture from a daemon GraphQL endpoint")]
struct Cli {
    #[arg(long, value_enum, default_value_t = Network::MesaMut)]
    network: Network,

    /// Override the endpoint (otherwise determined by --network).
    #[arg(long)]
    endpoint: Option<String>,

    /// Output directory. Will be created.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let endpoint = cli
        .endpoint
        .clone()
        .unwrap_or_else(|| cli.network.endpoint().to_string());

    fs::create_dir_all(&cli.out)
        .with_context(|| format!("create_dir_all {}", cli.out.display()))?;

    eprintln!("Fetching from {endpoint} ...");
    let resp_text = reqwest::blocking::Client::builder()
        .build()?
        .post(&endpoint)
        .json(&json!({ "query": QUERY }))
        .send()?
        .text()?;

    let resp: Value = serde_json::from_str(&resp_text)
        .with_context(|| format!("response was not JSON: {}", truncate(&resp_text, 200)))?;

    if let Some(errors) = resp.get("errors") {
        return Err(anyhow!("GraphQL errors: {}", errors));
    }
    let data = resp
        .get("data")
        .ok_or_else(|| anyhow!("response had no data field: {}", truncate(&resp_text, 200)))?;

    let vk = data
        .get("blockchainVerificationKey")
        .ok_or_else(|| anyhow!("response missing blockchainVerificationKey"))?;

    let best_chain = data
        .get("bestChain")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("response missing bestChain array"))?;
    let block = best_chain
        .first()
        .ok_or_else(|| anyhow!("bestChain is empty"))?;

    let state_hash = block
        .get("stateHashField")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing bestChain[0].stateHashField"))?;
    let base64_proof = block
        .get("protocolStateProof")
        .and_then(|p| p.get("base64"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing bestChain[0].protocolStateProof.base64"))?;

    // Mina daemon emits URL-safe base64 (alphabet uses `-` and `_`). Padding
    // is also optional in practice, so we accept either.
    let proof_bytes = base64::engine::general_purpose::URL_SAFE
        .decode(base64_proof)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(base64_proof))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(base64_proof))
        .context("base64 decode protocolStateProof.base64")?;

    let proof_path = cli.out.join("proof.bin_prot");
    let vk_path = cli.out.join("vk.json");
    let state_hash_path = cli.out.join("state_hash.txt");

    fs::write(&proof_path, &proof_bytes)
        .with_context(|| format!("write {}", proof_path.display()))?;
    fs::write(
        &vk_path,
        serde_json::to_string_pretty(vk).expect("serialize vk"),
    )
    .with_context(|| format!("write {}", vk_path.display()))?;
    fs::write(&state_hash_path, state_hash)
        .with_context(|| format!("write {}", state_hash_path.display()))?;

    eprintln!(
        "Wrote {} ({} bytes), {}, {} ({} bytes state hash)",
        proof_path.display(),
        proof_bytes.len(),
        vk_path.display(),
        state_hash_path.display(),
        state_hash.len()
    );
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…(truncated)", &s[..n])
    }
}
