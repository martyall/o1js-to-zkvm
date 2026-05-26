//! Out-of-circuit Pickles verifier.
//!
//! Layering:
//!
//!   * [`wire`] (std) — serde-deserializable form of the four OCaml-produced
//!     fixture files, plus parsing. Host-side only.
//!   * [`convert`] (std) — host-side conversion of the parsed wire data into
//!     the verifier types ([`Verifier::new`], [`OcamlProof::into_verifiable`]).
//!   * [`types`] (no_std) — the verifier types ([`Verifier`],
//!     [`VerifiableProof`]) consumed by the crate-root [`verify`] /
//!     [`verify_batch`] entry points. These run `no_std` + `alloc`, suitable
//!     for an SP1 guest.
//!
//! Primitives (Pasta fields/curves, Poseidon, kimchi `VerifierIndex` /
//! `ProverProof` serde, SRS/MSM, `batch_verify_with_rng`, the linearization
//! interpreter) come from upstream proof-systems crates; only the
//! pickles-specific glue is implemented here.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod deferred;
pub mod serialize;
pub mod types;

#[cfg(feature = "std")]
pub mod wire;

#[cfg(feature = "std")]
pub mod convert;

use alloc::vec::Vec;

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use mina_curves::pasta::Vesta;
use mina_poseidon::sponge::ScalarChallenge;
use poly_commitment::commitment::b_poly_coefficients;

use types::{StepField, VerifiableProof, Verifier};

/// Verify a single Pickles proof against its tag's [`Verifier`]. Deterministic
/// + `no_std`.
pub fn verify(verifier: &Verifier, proof: &VerifiableProof) -> bool {
    verify_batch(verifier, core::slice::from_ref(proof))
}

/// Verify a batch of proofs sharing one tag. Deterministic + `no_std`.
///
/// Three stages, AND-folded:
///   1. [`accumulator_check`] per proof.
///   2. Reconstruct each proof's wrap kimchi public input from its expanded
///      deferred values ([`deferred::expand_deferred`] +
///      [`deferred::wrap_public_input`]).
///   3. One amortized kimchi `batch_verify_with_rng` over the batch, seeded by
///      [`batching_rng`] (Fiat–Shamir-derived; see its doc for the soundness
///      argument).
pub fn verify_batch(verifier: &Verifier, proofs: &[VerifiableProof]) -> bool {
    use groupmap::GroupMap;
    use kimchi::verifier::{batch_verify_with_rng, Context};
    use mina_curves::pasta::{Pallas, PallasParameters};
    use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
    use mina_poseidon::pasta::FULL_ROUNDS;
    use mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
    use poly_commitment::commitment::CommitmentCurve;
    use poly_commitment::ipa::OpeningProof;
    use rand_chacha::ChaCha20Rng;
    use types::WrapField;

    if !proofs.iter().all(|p| accumulator_check(verifier, p)) {
        return false;
    }

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

    let mut rng = batching_rng(proofs, &pis);

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
    batch_verify_with_rng::<
        FULL_ROUNDS,
        Pallas,
        WrapFqSponge,
        WrapFrSponge,
        OpeningProof<Pallas, FULL_ROUNDS>,
        ChaCha20Rng,
    >(&group_map, &contexts, &mut rng)
    .is_ok()
}

/// Fiat–Shamir-derived `ChaCha20Rng` for kimchi's batched dlog check, seeded
/// by `blake2s(domain ‖ for each (proof, pi): postcard(proof) ‖ canonical(pi))`
/// with length prefixes.
///
/// Binding the random linear combination of the IPA verification equations to
/// the proof is what makes the batched check sound: a fixed/known seed would
/// let a prover forge an invalid proof whose specific combination vanishes.
/// `postcard` is used for the (serde-only) `ProverProof`; the public input
/// uses `CanonicalSerialize` (bare `Vec<Fq>` doesn't impl native serde
/// `Serialize`, only the proof's `serde_as` wrappers do).
fn batching_rng(
    proofs: &[VerifiableProof],
    pis: &[Vec<types::WrapField>],
) -> rand_chacha::ChaCha20Rng {
    use ark_serialize::CanonicalSerialize;
    use blake2::{Blake2s256, Digest};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    let mut hasher = Blake2s256::new();
    hasher.update(b"pickles-verifier/batch-dlog-rng/v1");
    for (p, pi) in proofs.iter().zip(pis.iter()) {
        let proof_bytes = postcard::to_allocvec(&p.wrap_proof).expect("serialize wrap proof");
        hasher.update((proof_bytes.len() as u64).to_le_bytes());
        hasher.update(&proof_bytes);
        let mut pi_bytes = Vec::new();
        pi.serialize_compressed(&mut pi_bytes)
            .expect("serialize public input");
        hasher.update((pi_bytes.len() as u64).to_le_bytes());
        hasher.update(&pi_bytes);
    }
    ChaCha20Rng::from_seed(hasher.finalize().into())
}

/// Stage 2: the IPA accumulator check. The proof's
/// `challenge_polynomial_commitment` must equal `compute_sg(bulletproof_challenges)`,
/// the non-hiding MSM of the IPA challenge polynomial `b(X)`'s coefficients
/// against the Vesta SRS generators. Plain arkworks MSM rather than the
/// std-gated `SRS::commit_non_hiding`.
pub fn accumulator_check(verifier: &Verifier, proof: &VerifiableProof) -> bool {
    let chals: Vec<StepField> = proof
        .raw_bulletproof_challenges
        .iter()
        .map(|c| ScalarChallenge::new(*c).to_field(&verifier.step_endo))
        .collect();
    let coeffs = b_poly_coefficients(&chals);
    let g = &verifier.vesta_srs.g;
    let n = coeffs.len().min(g.len());
    let computed_sg = <<Vesta as AffineRepr>::Group as VariableBaseMSM>::msm(&g[..n], &coeffs[..n])
        .expect("compute_sg MSM")
        .into_affine();
    computed_sg == proof.challenge_polynomial_commitment
}

// The tests use `std::fs` to read fixture JSONs + `std::sync::OnceLock` for
// the shared SRSes, so they only build under `--features std`. The no_std
// build covers serialize's pod-layout tests (`mod serialize::tests`) and the
// wire/convert sibling modules' tests already gated by `cfg(feature = "std")`.
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::types::{VestaSrs, WrapSrs};
    use crate::wire::{parse_app_statement, parse_wrap_proof, parse_wrap_vk, OcamlProof};
    use mina_curves::pasta::Pallas;
    use poly_commitment::precomputed_srs::get_srs;
    use std::sync::{Arc, OnceLock};

    /// Shared Vesta SRS for the stage-2 accumulator MSM (loaded once from
    /// `proof-systems/srs/vesta.srs`).
    fn vesta_srs() -> &'static Arc<VestaSrs> {
        static SRS: OnceLock<Arc<VestaSrs>> = OnceLock::new();
        SRS.get_or_init(|| Arc::new(get_srs::<Vesta>()))
    }

    /// Shared Pallas SRS for the wrap dlog check (loaded once from
    /// `proof-systems/srs/pallas.srs`).
    fn wrap_srs() -> &'static Arc<WrapSrs> {
        static SRS: OnceLock<Arc<WrapSrs>> = OnceLock::new();
        SRS.get_or_init(|| Arc::new(get_srs::<Pallas>()))
    }

    fn fixture(dir: &str, file: &str) -> String {
        let path = format!("{}/../../fixtures/{dir}/{file}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }

    /// Full end-to-end out-of-circuit verification over the fixture matrix.
    /// A `Verifier` is built per fixture (each has its own wrap VK); SRSes are
    /// shared across iterations via `OnceLock`.
    #[test]
    fn verify_accepts_fixtures() {
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
            let verifier = Verifier::new(wrap_vk, wrap_srs().clone(), vesta_srs().clone(), 1);

            assert!(verify(&verifier, &vp), "verify should accept {dir}");
        }
    }

    /// Encode→decode round-trip: build a [`Verifier`] from the mainnet
    /// blockchain SNARK fixture, run it through
    /// [`serialize::encode_verifier_blob`] then [`serialize::decode_verifier_blob`],
    /// and confirm the decoded verifier (with a pod-cast SRS + pre-seeded
    /// wrap Lagrange basis) accepts the same proof. This is the path the SP1
    /// guest exercises.
    #[test]
    fn encode_decode_verifier_blob_round_trip_accepts() {
        let dir = "mainnet-blockchain-snark";
        let ocaml =
            OcamlProof::parse(&fixture(dir, "public_input_skeleton.json")).expect("skeleton");
        let wrap_vk = parse_wrap_vk(&fixture(dir, "vk.serde.json")).expect("vk");
        let wrap_proof = parse_wrap_proof(&fixture(dir, "proof.serde.json")).expect("proof");
        let stmt = parse_app_statement(&fixture(dir, "app_statement.json")).expect("stmt");
        let vp = ocaml
            .into_verifiable(wrap_proof, &wrap_vk, &[stmt])
            .expect("conversion");

        // Encode at host side (basis is computed from the wrap SRS at wrap_vk's
        // domain), then decode (basis is seeded into the new SRS's cache).
        let blob = crate::serialize::encode_verifier_blob(
            vesta_srs(),
            wrap_srs(),
            /* step_num_chunks */ 1,
            &wrap_vk,
        );
        // The decoder needs 8-byte alignment, which `Vec<u8>` already provides
        // on this platform (the underlying allocator returns max-aligned
        // blocks). The SP1 guest gets it from a `#[repr(C, align(8))]` wrapper
        // around `include_bytes!`.
        assert_eq!(blob.as_ptr() as usize % 8, 0, "blob ptr must be 8-aligned");
        let decoded = crate::serialize::decode_verifier_blob(&blob);

        assert!(
            verify(&decoded, &vp),
            "decoded verifier should accept mainnet blockchain SNARK"
        );
    }
}
