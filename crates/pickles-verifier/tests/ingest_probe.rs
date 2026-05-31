//! M2 probe + M3 structural checks for the bin_prot ingestion path.
//!
//! - M2: confirm `mina_p2p_messages` can decode the bin_prot bytes from each
//!   target network (mesa MUT + mainnet).
//! - M3: confirm structural invariants on the decoded statement (mpv, IPA
//!   rounds, proofs-verified mask). Full `verify` path is gated on the wrap
//!   kimchi `ProverProof` reconstruction (M3 follow-up).

#![cfg(feature = "ingest-bin-prot")]

use pickles_verifier::ingest::bin_prot::{decode_bytes, to_wrap_proof};
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
    let bytes = std::fs::read(dir.join("proof.bin_prot")).expect("read proof");
    println!("[{network_dir}] proof.bin_prot = {} bytes", bytes.len());
    let _parsed = decode_bytes(&bytes)
        .unwrap_or_else(|e| panic!("bin_prot decode failed for {network_dir}: {e}"));
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

/// Structural check on the decoded `MinaBaseProofStableV2` statement — mpv,
/// IPA rounds, proofs-verified mask. The full `verify` path needs the wrap
/// kimchi `ProverProof` reconstruction (an M3 follow-up that's still
/// outstanding), so for now we assert that builder errors with the expected
/// TODO message.
fn structural_check(network_dir: &str, expected_mpv: usize) {
    let dir = fixture_dir(network_dir);
    let bytes = std::fs::read(dir.join("proof.bin_prot")).expect("read proof");
    let parsed = decode_bytes(&bytes).expect("bin_prot decode");

    // Wrap-proof builder is implemented; both networks should produce a
    // valid ProverProof structurally (verify is a separate concern that
    // also needs the matching VK — see `ingest_verify::verify_mainnet_tip`).
    to_wrap_proof(&parsed.0).unwrap_or_else(|e| panic!("to_wrap_proof: {e}"));

    let st = &parsed.0.statement;
    let actual_mpv = st
        .messages_for_next_step_proof
        .challenge_polynomial_commitments
        .len();
    assert_eq!(
        actual_mpv, expected_mpv,
        "mpv = challenge_polynomial_commitments len"
    );
    assert_eq!(
        st.proof_state.deferred_values.bulletproof_challenges.0.len(),
        16,
        "step IPA rounds = 16"
    );

    // Blockchain SNARK has proofs_verified = N2 -> mask [true, true].
    let mask = match st.proof_state.deferred_values.branch_data.proofs_verified {
        mina_p2p_messages::v2::PicklesBaseProofsVerifiedStableV1::N0 => [false, false],
        mina_p2p_messages::v2::PicklesBaseProofsVerifiedStableV1::N1 => [false, true],
        mina_p2p_messages::v2::PicklesBaseProofsVerifiedStableV1::N2 => [true, true],
    };
    println!(
        "[{network_dir}] mpv={actual_mpv}, domain_log2={}, mask={:?}",
        st.proof_state.deferred_values.branch_data.domain_log2.0 .0 as u8,
        mask,
    );
    assert_eq!(mask, [true, true], "blockchain SNARK should have N2 mask");
}

#[test]
fn structural_mainnet() {
    structural_check("mainnet-tip", 2);
}

#[test]
fn structural_mesa_mut() {
    structural_check("mesa-mut-tip", 2);
}
