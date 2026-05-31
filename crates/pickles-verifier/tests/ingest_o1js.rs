//! End-to-end verification of an o1js ZkProgram proof via the new sexpr
//! ingestion path.
//!
//! Loads `fixtures/o1js-zkprogram/{proof.json,verificationKey.json}`:
//!   * proof: `Proof.toJSON()` with base64 of OCaml `sexp_of_t` text in `proof`
//!   * VK: `{ data: base64 of bin_prot, hash: decimal Fp }`
//!
//! The circuit is `Adder.double` (publicInput: Field, publicOutput: Field).
//! For `x = 7`, `out = 14`. The pickles statement is
//! `[publicInput, publicOutput]`, so `app_state = [Fp(7), Fp(14)]`.

#![cfg(feature = "ingest-bin-prot")]

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use mina_curves::pasta::{Fp, Vesta};
use pickles_verifier::ingest::o1js::parse_to_verifiable;
use pickles_verifier::ingest::o1js_vk::parse_o1js_vk;
use pickles_verifier::types::{StepField, Verifier};
use pickles_verifier::verify;
use poly_commitment::precomputed_srs::get_srs;
use serde::Deserialize;

fn workspace_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn fixture_dir(name: &str) -> PathBuf {
    workspace_dir().join("fixtures").join(name)
}

#[derive(Deserialize)]
struct O1jsProofEnvelope {
    #[serde(default, rename = "publicInput")]
    public_input: Vec<String>,
    #[serde(default, rename = "publicOutput")]
    public_output: Vec<String>,
}

fn parse_decimal(s: &str) -> StepField {
    Fp::from_str(s.trim()).expect("decimal Fp parse")
}

#[test]
fn verify_o1js_zkprogram_adder() {
    let dir = fixture_dir("o1js-zkprogram");
    let proof_json =
        std::fs::read_to_string(dir.join("proof.json")).expect("read proof.json");
    let vk_json =
        std::fs::read_to_string(dir.join("verificationKey.json")).expect("read vk.json");

    // Build app_state = [publicInput..., publicOutput...] (Adder.double: 1 each).
    let envelope: O1jsProofEnvelope =
        serde_json::from_str(&proof_json).expect("envelope parse");
    let mut app_state: Vec<StepField> = Vec::new();
    for s in &envelope.public_input {
        app_state.push(parse_decimal(s));
    }
    for s in &envelope.public_output {
        app_state.push(parse_decimal(s));
    }
    println!(
        "[o1js-zkprogram] app_state len={} input={:?} output={:?}",
        app_state.len(),
        envelope.public_input,
        envelope.public_output,
    );

    // Template VK supplies universal-wrap math params (domain, shifts, etc).
    let template_vk_json =
        std::fs::read_to_string(fixture_dir("nrr").join("vk.serde.json"))
            .expect("read template vk");
    let wrap_vk = parse_o1js_vk(&vk_json, &template_vk_json).expect("o1js VK build");

    let vp = parse_to_verifiable(&proof_json, &wrap_vk, &app_state)
        .expect("o1js proof → VerifiableProof");

    let wrap_srs: Arc<_> = Arc::new(get_srs::<mina_curves::pasta::Pallas>());
    let vesta_srs: Arc<_> = Arc::new(get_srs::<Vesta>());
    let verifier = Verifier::new(wrap_vk, wrap_srs, vesta_srs, /* step_num_chunks */ 1);

    let ok = verify(&verifier, &vp);
    println!("[o1js-zkprogram] verify: {ok}");
    assert!(ok, "o1js ZkProgram proof should verify");
}
