//! M4–M5: end-to-end verification of bin_prot fixtures via the
//! `ingest::bin_prot` adapter. Builds a `VerifiableProof` from the
//! daemon-fetched proof bytes (using the existing mainnet wrap VK), then
//! runs `pickles_verifier::verify`.

#![cfg(feature = "ingest-bin-prot")]

use mina_curves::pasta::{Fp, Vesta};
use std::str::FromStr;
use pickles_verifier::ingest::bin_prot::to_verifiable_proof;
use pickles_verifier::types::{StepField, Verifier};
use pickles_verifier::wire::parse_wrap_vk;
use pickles_verifier::verify;
use poly_commitment::precomputed_srs::get_srs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("fixtures")
        .join(name)
}

fn read(path: PathBuf) -> Vec<u8> {
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Parse a decimal field-element string (the daemon's `stateHashField` form).
fn parse_decimal_field(s: &str) -> StepField {
    Fp::from_str(s.trim()).expect("state hash field decimal parse")
}

fn verify_fixture(network_dir: &str) {
    let dir = fixture_dir(network_dir);
    let bytes = read(dir.join("proof.bin_prot"));
    let state_hash_decimal =
        String::from_utf8(read(dir.join("state_hash.txt"))).expect("state hash utf8");
    let app_state = [parse_decimal_field(&state_hash_decimal)];

    // For the mainnet blockchain SNARK the wrap VK is a network constant, and
    // we already have it in the canonical kimchi-Rust-serde form under
    // `fixtures/mainnet-blockchain-snark/vk.serde.json`. The daemon-served
    // `vk.json` is in OCaml-pickles-yojson shape (commitments + index +
    // data) which would need its own parser to convert; that's an M3 follow-up.
    let vk_json = std::fs::read_to_string(
        fixture_dir("mainnet-blockchain-snark").join("vk.serde.json"),
    )
    .expect("read mainnet wrap VK serde JSON");
    let wrap_vk = parse_wrap_vk(&vk_json).expect("parse mainnet wrap VK");

    let vp = to_verifiable_proof(&bytes, &wrap_vk, &app_state).unwrap_or_else(|e| {
        panic!("[{network_dir}] to_verifiable_proof: {e}");
    });

    let wrap_srs: Arc<_> = Arc::new(get_srs::<mina_curves::pasta::Pallas>());
    let vesta_srs: Arc<_> = Arc::new(get_srs::<Vesta>());
    let verifier = Verifier::new(wrap_vk, wrap_srs, vesta_srs, /* step_num_chunks */ 1);

    let ok = verify(&verifier, &vp);
    println!("[{network_dir}] verify: {ok}");
    assert!(ok, "[{network_dir}] verify should accept the bin_prot proof");
}

/// Mainnet path is the one where we expect success: blockchain VK is fixed
/// across the network, and the proof bytes we fetched are from the same
/// mainnet daemon the existing fixture VK is keyed to.
#[test]
fn verify_mainnet_tip() {
    verify_fixture("mainnet-tip");
}

/// Mesa MUT path is allowed to fail with a documented reason — different
/// blockchain VK from mainnet. Marked `#[ignore]` so it doesn't gate CI; run
/// with `cargo test -- --include-ignored` to attempt it.
#[test]
#[ignore = "mesa MUT uses a different blockchain VK than mainnet; would need its own VK"]
fn verify_mesa_mut_tip() {
    verify_fixture("mesa-mut-tip");
}
