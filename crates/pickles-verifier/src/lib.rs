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

pub mod deferred;
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
///
/// `std`-only: the stage-3 dlog check delegates to kimchi's `batch_verify`,
/// which draws batching randomness from `thread_rng`. The no_std core exposes
/// the building blocks ([`accumulator_check`], [`deferred::expand_deferred`],
/// [`deferred::wrap_public_input`]) for a guest-side dlog check.
#[cfg(feature = "std")]
pub fn verify(verifier: &Verifier, proof: &VerifiableProof) -> bool {
    verify_batch(verifier, core::slice::from_ref(proof))
}

/// Verify a batch of proofs sharing one tag. PS `Pickles.Verify.verifyBatch`.
///
/// Three stages, AND-folded:
///   1. **Expand deferred values** — reconstruct the wrap deferred-values
///      output from the carried minimal skeleton ([`deferred::expand_deferred`]):
///      sponge replay → `xi`/`r`, combined-inner-product, and `ft_eval0` via the
///      kimchi linearization interpreter. PS `expandDeferredForVerify`.
///   2. **IPA-step accumulator check** ([`accumulator_check`]) —
///      `compute_sg(expanded bp challenges)` on the Vesta SRS must equal
///      `challenge_polynomial_commitment`.
///   3. **Wrap opening-proof / dlog check** — assemble each proof's wrap kimchi
///      public input from its expanded deferred values + message digests
///      ([`deferred::wrap_public_input`]), then run ONE amortized kimchi
///      `batch_verify` over all `(wrap_vk, wrap_proof, public_input)`. PS
///      `verifyOpeningProofsBatch`.
#[cfg(feature = "std")]
pub fn verify_batch(verifier: &Verifier, proofs: &[VerifiableProof]) -> bool {
    use groupmap::GroupMap;
    use kimchi::verifier::{batch_verify, Context};
    use mina_curves::pasta::{Pallas, PallasParameters};
    use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
    use mina_poseidon::pasta::FULL_ROUNDS;
    use mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
    use poly_commitment::commitment::CommitmentCurve;
    use poly_commitment::ipa::OpeningProof;
    use types::WrapField;

    // Stage 2 (accumulator check) per proof, AND-folded with short-circuit.
    if !proofs.iter().all(|p| accumulator_check(verifier, p)) {
        return false;
    }

    // Stage 1: reconstruct each proof's wrap kimchi public input.
    let pis: Vec<Vec<WrapField>> = proofs
        .iter()
        .map(|p| {
            let dv = deferred::expand_deferred(verifier, p);
            deferred::wrap_public_input(
                &dv,
                p.messages_for_next_step_proof_digest,
                p.messages_for_next_wrap_proof_digest,
            )
        })
        .collect();

    // Stage 3: one amortized kimchi `batch_verify` over the wrap proofs.
    let contexts: Vec<Context<FULL_ROUNDS, Pallas, OpeningProof<Pallas, FULL_ROUNDS>, _>> = proofs
        .iter()
        .zip(pis.iter())
        .map(|(p, pi)| Context {
            verifier_index: &verifier.wrap_vk,
            proof: &p.wrap_proof,
            public_input: pi.as_slice(),
        })
        .collect();

    let group_map = <Pallas as CommitmentCurve>::Map::setup();
    type WrapFqSponge = DefaultFqSponge<PallasParameters, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
    type WrapFrSponge = DefaultFrSponge<WrapField, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;
    batch_verify::<FULL_ROUNDS, Pallas, WrapFqSponge, WrapFrSponge, OpeningProof<Pallas, FULL_ROUNDS>>(
        &group_map,
        &contexts,
    )
    .is_ok()
}

/// Stage 2 — the IPA-step accumulator check. The proof's
/// `challenge_polynomial_commitment` must equal `compute_sg` of the (endo-
/// expanded) bulletproof challenges: the non-hiding commitment to the IPA
/// challenge polynomial `b(X)` on the step (`Vesta`) SRS. PS
/// `Ipa.Step.accumulator_check` via `vestaSrsBPolyCommitmentPoint`. `no_std`.
pub fn accumulator_check(verifier: &Verifier, proof: &VerifiableProof) -> bool {
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
    use crate::types::{VestaSrs, WrapSrs, STEP_IPA_ROUNDS};
    use crate::wire::{parse_app_statement, parse_wrap_proof, parse_wrap_vk, OcamlProof};
    use std::sync::Arc;

    /// A tiny Pallas SRS for stages 1+2 (which never touch the wrap SRS).
    fn tiny_wrap_srs() -> Arc<WrapSrs> {
        Arc::new(WrapSrs::create(1 << 4))
    }

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
        let verifier = Verifier::new(seed_vk, tiny_wrap_srs(), vesta_srs, 16, 1).expect("verifier");

        for dir in [
            "mainnet-blockchain-snark",
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

    /// Stage 1 over the fixture matrix. Exercises `deferred::expand_deferred`:
    /// the kimchi `oracles_from_digest` replay + the pickles glue (CIP,
    /// `derive_plonk`, bulletproof `b`) must run without panicking and produce
    /// non-trivial field values for every proof. (Full correctness is gated by
    /// the not-yet-wired stage 3; here we smoke-test that the reconstruction
    /// runs end-to-end on real fixtures.) Stage 1 ignores the Vesta SRS, so a
    /// tiny one is built to keep the test fast. The step circuits are `nc = 1`
    /// (`zk_rows = 3`); the per-proof step domain comes from each proof.
    #[test]
    fn expand_deferred_runs_on_fixtures() {
        use crate::deferred::expand_deferred;
        use ark_ff::Zero;

        let vesta_srs = VestaSrs::create(1 << 4);
        let seed_vk = parse_wrap_vk(&fixture("nrr", "vk.serde.json")).expect("vk");
        let verifier = Verifier::new(seed_vk, tiny_wrap_srs(), vesta_srs, 16, 1).expect("verifier");

        for dir in [
            "mainnet-blockchain-snark",
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

            let dv = expand_deferred(&verifier, &vp);

            assert!(!dv.combined_inner_product.is_zero(), "{dir}: cip nonzero");
            assert!(!dv.b.is_zero(), "{dir}: b nonzero");
            assert!(!dv.perm.is_zero(), "{dir}: perm nonzero");
            assert!(!dv.ft_eval0.is_zero(), "{dir}: ft_eval0 nonzero");
            assert!(!dv.r.is_zero(), "{dir}: r nonzero");
        }
    }

    /// Full end-to-end out-of-circuit verification (all three stages) over the
    /// fixture matrix. Each proof must verify against ITS OWN wrap VK, so a
    /// `Verifier` is built per fixture (unlike stages 1+2, where the wrap VK is
    /// irrelevant). The Vesta SRS (stage 2, 2^16) and Pallas SRS (stage 3, the
    /// wrap VK's `max_poly_size`) are built once; the Pallas SRS is shared via
    /// `Arc` so the wrap lagrange basis is computed once. `verify` must accept
    /// every real proof (NRR mpv=0, simple_chain mpv=1, tree_proof_return mpv=2).
    #[test]
    fn verify_accepts_fixtures() {
        let vesta_srs = VestaSrs::create(1 << STEP_IPA_ROUNDS);
        let seed_vk = parse_wrap_vk(&fixture("nrr", "vk.serde.json")).expect("vk");
        let wrap_srs = Arc::new(WrapSrs::create(seed_vk.max_poly_size));

        for dir in [
            "mainnet-blockchain-snark",
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

            let step_domain_log2 = ocaml.step_domain_log2 as usize;
            let vp = ocaml
                .into_verifiable(wrap_proof, &wrap_vk, &[stmt])
                .expect("conversion");
            let verifier = Verifier::new(
                wrap_vk,
                wrap_srs.clone(),
                vesta_srs.clone(),
                step_domain_log2,
                1,
            )
            .expect("verifier");

            assert!(verify(&verifier, &vp), "verify should accept {dir}");
        }
    }
}
