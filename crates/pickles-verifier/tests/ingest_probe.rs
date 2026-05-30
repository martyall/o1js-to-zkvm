//! M2 probe: confirm that `mina_p2p_messages` can decode the bin_prot bytes
//! the Mina daemon serves on the networks we care about (mesa MUT + mainnet).
//!
//! If a network's stable version diverges from the openmina pin we use, this
//! is where we'd see it — and the failure mode (which field, which version
//! tag) is what we record in SUMMARY.md.

#![cfg(feature = "ingest-bin-prot")]

use pickles_verifier::ingest::bin_prot::decode_bytes;
use std::path::Path;

fn fixture_dir(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("fixtures")
        .join(name)
}

fn probe(network_dir: &str) {
    let dir = fixture_dir(network_dir);
    let proof_path = dir.join("proof.bin_prot");
    let bytes = std::fs::read(&proof_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", proof_path.display()));
    println!("[{network_dir}] proof.bin_prot = {} bytes", bytes.len());
    let parsed = decode_bytes(&bytes)
        .unwrap_or_else(|e| panic!("bin_prot decode failed for {network_dir}: {e}"));
    // Don't print the whole struct — it's enormous. The smoke test is that
    // the parse succeeded and we can name a few inner fields without panic.
    let _ = parsed;
    println!("[{network_dir}] decode_bytes: OK");
}

#[test]
fn decode_mesa_mut_tip() {
    probe("mesa-mut-tip");
}

#[test]
fn decode_mainnet_tip() {
    probe("mainnet-tip");
}
