//! Out-of-circuit Pickles verifier, translated from the PureScript
//! `Pickles.Verify` + `Test.Pickles.Sideload.Loader`.
//!
//! Layering mirrors the PureScript side:
//!
//!   * [`wire`] (std) — the serde-deserializable form of the four
//!     OCaml-serialized fixture files, plus parsing. Host-side only.
//!   * [`convert`] (std) — host-side conversion of the parsed wire data
//!     into the verifier types (`Verifier::new` + `OcamlProof::into_verifiable`);
//!     port of the PureScript `Test.Pickles.Sideload.Loader` + `mkVerifier`.
//!   * [`types`] (no_std) — the verifier types (`Verifier`, `VerifiableProof`),
//!     consumed by the crate-root [`verify`] / [`verify_batch`] entry points.
//!     These run `no_std` + `alloc` so they work in the SP1 guest.
//!
//! Primitives (Pasta fields/curves, Poseidon, the kimchi `VerifierIndex` /
//! `ProverProof` serde, SRS/MSM, `batch_verify`, the linearization
//! interpreter) come from the upstream proof-systems crates — only the
//! pickles-specific glue is translated here.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod types;

#[cfg(feature = "std")]
pub mod wire;

#[cfg(feature = "std")]
pub mod convert;

use alloc::vec::Vec;

use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use mina_poseidon::sponge::ScalarChallenge;
use poly_commitment::commitment::b_poly_coefficients;
use poly_commitment::SRS;

use types::{StepField, VerifiableProof, Verifier};

/// Fully verify a single Pickles proof against its tag's [`Verifier`].
/// PS `Pickles.Verify.verify` (`verify v p = verifyBatch v [p]`).
pub fn verify(verifier: &Verifier, proof: &VerifiableProof) -> bool {
    verify_batch(verifier, core::slice::from_ref(proof))
}

/// Verify a batch of proofs sharing one tag. PS `Pickles.Verify.verifyBatch`.
///
/// Each proof runs two independent stages that are AND-folded:
///   1. **Expand deferred values** — reconstruct the wrap deferred-values
///      output from the carried minimal skeleton: sponge replay → `xi`/`r`,
///      combined-inner-product, and `ft_eval0` via the kimchi linearization
///      interpreter (`PolishToken::evaluate`). PS `expandDeferredForVerify`.
///   2. **IPA-step accumulator check** — `compute_sg(expanded bp challenges)`
///      on the Vesta SRS must equal `challenge_polynomial_commitment`.
///
/// Stage 3 (the kimchi opening-proof / dlog check) is then amortized into a
/// single `batch_verify` over every proof's reconstructed wrap public input
/// (assembled from the expanded deferred values + the two message digests).
pub fn verify_batch(verifier: &Verifier, proofs: &[VerifiableProof]) -> bool {
    // Stage 2 (accumulator check) per proof, AND-folded with short-circuit.
    if !proofs.iter().all(|p| accumulator_check(verifier, p)) {
        return false;
    }
    // Stages 1 + 3 (expand deferred values → wrap public input → batched dlog
    // check) remain.
    todo!("step 3: stage 1 expand + wrap public input + batched dlog check")
}

/// Stage 2 — the IPA-step accumulator check. The proof's
/// `challenge_polynomial_commitment` must equal `compute_sg` of the (endo-
/// expanded) bulletproof challenges: the non-hiding commitment to the IPA
/// challenge polynomial `b(X)` on the step (`Vesta`) SRS. PS
/// `Ipa.Step.accumulator_check` via `vestaSrsBPolyCommitmentPoint`.
fn accumulator_check(verifier: &Verifier, proof: &VerifiableProof) -> bool {
    let chals: Vec<StepField> = proof
        .raw_bulletproof_challenges
        .iter()
        .map(|c| ScalarChallenge::new(*c).to_field(&verifier.step_endo))
        .collect();
    let b_poly = DensePolynomial::from_coefficients_vec(b_poly_coefficients(&chals));
    let computed_sg = verifier.vesta_srs.commit_non_hiding(&b_poly, 1).chunks[0];
    computed_sg == proof.challenge_polynomial_commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{VestaSrs, STEP_IPA_ROUNDS};
    use crate::wire::{parse_app_statement, parse_wrap_proof, parse_wrap_vk, OcamlProof};

    fn fixture(dir: &str, file: &str) -> String {
        let path = format!("{}/../../fixtures/{dir}/{file}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }

    /// Stage 2 over the fixture matrix. The step (`Vesta`) SRS is built once at
    /// 2^16 (`STEP_IPA_ROUNDS`); `step_endo` + SRS are fixture-independent, so a
    /// single `Verifier` covers every proof's accumulator check. Each real proof
    /// must be accepted: its `challenge_polynomial_commitment` equals `compute_sg`
    /// of the endo-expanded bulletproof challenges.
    #[test]
    fn accumulator_check_accepts_fixtures() {
        let vesta_srs = VestaSrs::create(1 << STEP_IPA_ROUNDS);

        // Build one verifier (only step_endo + vesta_srs matter for stage 2).
        let seed_vk = parse_wrap_vk(&fixture("nrr", "vk.serde.json")).expect("vk");
        let verifier = Verifier::new(seed_vk, vesta_srs, 16, 1).expect("verifier");

        for dir in [
            "nrr",
            "simplechain/wrap0",
            "simplechain/wrap1",
            "simplechain/wrap2",
            "treeproofreturn/wrap0",
            "treeproofreturn/wrap1",
            "treeproofreturn/wrap2",
        ] {
            let ocaml =
                OcamlProof::parse(&fixture(dir, "public_input_skeleton.json")).expect("skeleton");
            let wrap_vk = parse_wrap_vk(&fixture(dir, "vk.serde.json")).expect("vk");
            let wrap_proof = parse_wrap_proof(&fixture(dir, "proof.serde.json")).expect("proof");
            let stmt = parse_app_statement(&fixture(dir, "app_statement.json")).expect("stmt");
            let vp = ocaml
                .into_verifiable(wrap_proof, &wrap_vk, &[stmt])
                .expect("conversion");

            assert!(
                accumulator_check(&verifier, &vp),
                "accumulator check should accept {dir}"
            );
        }
    }
}
