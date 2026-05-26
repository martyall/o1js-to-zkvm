//! Host-side conversion (`std`): parsed OCaml fixture wire data → the no_std
//! verifier types.
//!
//! Runs host-side so it allocates freely and uses `std`-only primitives
//! (kimchi domain/shifts, mina-poseidon, blake2s). Its output —
//! [`Verifier`] / [`VerifiableProof`] — is what the `no_std` verifier consumes.
//!
//! Every primitive is reused from upstream proof-systems crates:
//!   * `ScalarChallenge::to_field` — the endo expansion of a 128-bit challenge
//!     (Halo §6.2) to an effective scalar.
//!   * `poly_commitment::ipa::endos` — scalar endo coefficients.
//!   * `ArithmeticSponge<_, PlonkSpongeConstantsKimchi>` — Mina Poseidon
//!     `Random_oracle.hash` (zero init, absorb, squeeze).
//!   * kimchi `Radix2EvaluationDomain` + `permutation::Shifts` — step domain
//!     generator + permutation shifts.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use blake2::{Blake2s256, Digest};
use mina_curves::pasta::{Pallas, Vesta};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::{fp_kimchi, fq_kimchi, FULL_ROUNDS};
use mina_poseidon::poseidon::{ArithmeticSponge, Sponge};
use mina_poseidon::sponge::ScalarChallenge;
use poly_commitment::ipa::endos;

use crate::types::{
    StepField, VerifiableProof, WrapField, WrapProof, WrapVerifierIndex, STEP_IPA_ROUNDS,
    WRAP_IPA_ROUNDS,
};
use crate::wire::OcamlProof;

/// `Wrap_hack.Padded_length.n` — the message-for-next-wrap challenge vector is
/// front-padded with dummies up to this length.
const PADDED_LENGTH: usize = 2;

// ---------------------------------------------------------------------------
// 128-bit challenge endo expansion.
// ---------------------------------------------------------------------------

/// Expand a raw 128-bit challenge (already a field element < 2^128) to its
/// effective scalar via the curve endomorphism (Halo §6.2).
fn expand<F: ark_ff::PrimeField>(raw: F, endo: &F) -> F {
    ScalarChallenge::new(raw).to_field(endo)
}

// ---------------------------------------------------------------------------
// Wrap VK → step-hash field absorption order.
// ---------------------------------------------------------------------------

/// The wrap VK commitment coordinates in the order
/// `Common.hash_messages_for_next_step_proof` absorbs them: `sigma[0..6]`,
/// `coefficients[0..14]`, then `generic, psm, complete_add, mul, emul,
/// endomul_scalar` — each commitment's chunk-0 `(x, y)`.
///
/// The wrap VK is fixed to one chunk per commitment (`num_chunks_by_default = 1`).
/// Coords are Pallas base = Fp = `StepField` (no cross-field cast).
fn wrap_vk_step_fields(vk: &WrapVerifierIndex) -> Result<Vec<StepField>, String> {
    let index_comms = [
        &vk.generic_comm,
        &vk.psm_comm,
        &vk.complete_add_comm,
        &vk.mul_comm,
        &vk.emul_comm,
        &vk.endomul_scalar_comm,
    ];
    // 7 sigma + 15 coeff + 6 index commitments, 2 coords each.
    vk.sigma_comm
        .iter()
        .chain(vk.coefficients_comm.iter())
        .chain(index_comms)
        .try_fold(Vec::with_capacity((7 + 15 + 6) * 2), |mut out, pc| {
            let p = pc
                .chunks
                .first()
                .ok_or_else(|| "wrap VK commitment has no chunks".to_string())?;
            out.push(p.x);
            out.push(p.y);
            Ok(out)
        })
}

// ---------------------------------------------------------------------------
// Dummy IPA wrap challenges.
// ---------------------------------------------------------------------------

/// The 15 dummy wrap IPA challenges, endo-expanded — port of OCaml
/// `Dummy.Ipa.Wrap.challenges` (`ro.ml`). Each raw challenge `chal_i` is the
/// low 128 bits (LE) of `blake2s256("chal_i")`; the `Ro` monad draws them in
/// counter order `1..=15` and stores them reversed (`Vector.init` evaluates
/// right-to-left), so the result is indexed `[chal_15, …, chal_1]`.
fn dummy_ipa_wrap_expanded(wrap_endo: &WrapField) -> [WrapField; WRAP_IPA_ROUNDS] {
    let mut v: Vec<WrapField> = (1..=WRAP_IPA_ROUNDS)
        .map(|i| {
            let digest = Blake2s256::digest(format!("chal_{i}").as_bytes());
            let lo = u64::from_le_bytes(digest[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(digest[8..16].try_into().unwrap());
            ScalarChallenge::<WrapField>::from_limbs([lo, hi]).to_field(wrap_endo)
        })
        .collect();
    v.reverse();
    v.try_into()
        .unwrap_or_else(|_| unreachable!("exactly WRAP_IPA_ROUNDS produced"))
}

// ---------------------------------------------------------------------------
// Message digests.
// ---------------------------------------------------------------------------

/// `Common.hash_messages_for_next_step_proof`: hash the wrap VK fields, the
/// app-state fields, then per prev proof `(sg.x, sg.y, expanded bp challenges)`.
fn hash_messages_for_next_step(
    vk_fields: &[StepField],
    app_state: &[StepField],
    proofs: &[(Pallas, [StepField; STEP_IPA_ROUNDS])],
) -> StepField {
    let mut inputs = Vec::with_capacity(
        vk_fields.len() + app_state.len() + proofs.len() * (2 + STEP_IPA_ROUNDS),
    );
    inputs.extend_from_slice(vk_fields);
    inputs.extend_from_slice(app_state);
    for (sg, chals) in proofs {
        inputs.push(sg.x);
        inputs.push(sg.y);
        inputs.extend_from_slice(chals);
    }
    let mut sponge: ArithmeticSponge<StepField, PlonkSpongeConstantsKimchi, FULL_ROUNDS> =
        Sponge::new(fp_kimchi::static_params());
    sponge.absorb(&inputs);
    sponge.squeeze()
}

/// `Wrap_hack.hash_messages_for_next_wrap_proof`: flatten the padded challenge
/// vectors, then append `sg.x, sg.y` (the challenge-polynomial commitment).
fn hash_messages_for_next_wrap(
    cpc: &Vesta,
    padded_challenges: &[[WrapField; WRAP_IPA_ROUNDS]],
) -> WrapField {
    let mut inputs: Vec<WrapField> =
        Vec::with_capacity(padded_challenges.len() * WRAP_IPA_ROUNDS + 2);
    for chals in padded_challenges {
        inputs.extend_from_slice(chals);
    }
    inputs.push(cpc.x);
    inputs.push(cpc.y);
    let mut sponge: ArithmeticSponge<WrapField, PlonkSpongeConstantsKimchi, FULL_ROUNDS> =
        Sponge::new(fq_kimchi::static_params());
    sponge.absorb(&inputs);
    sponge.squeeze()
}

// ---------------------------------------------------------------------------
// Public conversion entry points.
// ---------------------------------------------------------------------------

impl OcamlProof {
    /// Consume the parsed wire skeleton into a canonical [`VerifiableProof`]:
    ///   * carry the 9 fields straight from the wire,
    ///   * endo-expand the prev step bp challenges into
    ///     `old_bulletproof_challenges`,
    ///   * recompute the two message digests (the wire erases them).
    ///
    /// The kimchi wrap proof + VK come from the sibling `proof.serde.json` /
    /// `vk.serde.json`. `app_state` is the application statement's field
    /// encoding (OCaml `Statement_value.to_field_elements`); for the
    /// single-field fixture statements it is `[statement]`.
    pub fn into_verifiable(
        self,
        wrap_proof: WrapProof,
        wrap_vk: &WrapVerifierIndex,
        app_state: &[StepField],
    ) -> Result<VerifiableProof, String> {
        // Scalar endo coefficients: `endos::<G>() = (base, scalar)`, take the
        // scalar `.1`. Step = `endos::<Vesta>().1` (Fp), wrap =
        // `endos::<Pallas>().1` (Fq).
        let step_endo = endos::<Vesta>().1;
        let wrap_endo = endos::<Pallas>().1;

        // Prev step bp challenges, endo-expanded (16-round) — these double as
        // `old_bulletproof_challenges` and as the per-proof challenges in the
        // step-message digest.
        let old_bulletproof_challenges: Vec<[StepField; STEP_IPA_ROUNDS]> = self
            .prev_step_chals_raw
            .iter()
            .map(|&chals| chals.map(|c| expand(c, &step_endo)))
            .collect();

        // Prev wrap bp challenges, endo-expanded (15-round) — for the wrap
        // digest.
        let prev_wrap_expanded: Vec<[WrapField; WRAP_IPA_ROUNDS]> = self
            .prev_wrap_chals_raw
            .iter()
            .map(|&chals| chals.map(|c| expand(c, &wrap_endo)))
            .collect();

        // messages_for_next_step_proof digest.
        let vk_fields = wrap_vk_step_fields(wrap_vk)?;
        let step_proofs: Vec<(Pallas, [StepField; STEP_IPA_ROUNDS])> = self
            .prev_step_sgs
            .iter()
            .copied()
            .zip(old_bulletproof_challenges.iter().copied())
            .collect();
        let messages_for_next_step_proof_digest =
            hash_messages_for_next_step(&vk_fields, app_state, &step_proofs);

        // messages_for_next_wrap_proof digest — front-pad to `PADDED_LENGTH`
        // with dummy wrap challenges (`Wrap_hack.pad_challenges`).
        let mpv = prev_wrap_expanded.len();
        if mpv > PADDED_LENGTH {
            return Err(format!(
                "prev wrap proofs ({mpv}) exceed padded length {PADDED_LENGTH}"
            ));
        }
        let dummy = dummy_ipa_wrap_expanded(&wrap_endo);
        let mut padded: Vec<[WrapField; WRAP_IPA_ROUNDS]> = Vec::with_capacity(PADDED_LENGTH);
        padded.resize(PADDED_LENGTH - mpv, dummy);
        padded.extend_from_slice(&prev_wrap_expanded);
        let messages_for_next_wrap_proof_digest =
            hash_messages_for_next_wrap(&self.challenge_polynomial_commitment, &padded);

        Ok(VerifiableProof {
            wrap_proof,
            raw_plonk: self.raw_plonk,
            raw_bulletproof_challenges: self.raw_bulletproof_challenges,
            branch_data: self.branch_data,
            sponge_digest_before_evaluations: self.sponge_digest_before_evaluations,
            prev_evals: self.prev_evals,
            p_eval0_chunks: self.p_eval0_chunks,
            old_bulletproof_challenges,
            challenge_polynomial_commitment: self.challenge_polynomial_commitment,
            messages_for_next_step_proof_digest,
            messages_for_next_wrap_proof_digest,
            step_domain_log2: self.step_domain_log2 as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{parse_app_statement, parse_wrap_proof, parse_wrap_vk};
    use ark_ff::Zero;

    /// Parse a fixture directory's four files, run `into_verifiable`, and
    /// assert the structural invariants the conversion must hold. Byte-exact
    /// digest correctness is validated transitively by `verify_accepts_fixtures`
    /// (a wrong digest → wrong wrap public input → kimchi check fails).
    fn convert(dir: &str, mpv: usize) -> VerifiableProof {
        let base = format!("{}/../../fixtures/{dir}", env!("CARGO_MANIFEST_DIR"));
        let read = |file: &str| {
            std::fs::read_to_string(format!("{base}/{file}"))
                .unwrap_or_else(|e| panic!("read {base}/{file}: {e}"))
        };

        let ocaml =
            OcamlProof::parse(&read("public_input_skeleton.json")).expect("skeleton parses");
        let wrap_vk = parse_wrap_vk(&read("vk.serde.json")).expect("vk parses");
        let wrap_proof = parse_wrap_proof(&read("proof.serde.json")).expect("proof parses");
        let stmt = parse_app_statement(&read("app_statement.json")).expect("app statement parses");

        let expected_log2 = ocaml.step_domain_log2 as usize;
        let vp = ocaml
            .into_verifiable(wrap_proof, &wrap_vk, &[stmt])
            .expect("conversion succeeds");

        assert_eq!(
            vp.old_bulletproof_challenges.len(),
            mpv,
            "old_bulletproof_challenges width = mpv"
        );
        assert!(
            !vp.messages_for_next_step_proof_digest.is_zero(),
            "step digest computed"
        );
        assert!(
            !vp.messages_for_next_wrap_proof_digest.is_zero(),
            "wrap digest computed"
        );
        assert_eq!(
            vp.step_domain_log2, expected_log2,
            "step domain log2 carried"
        );
        vp
    }

    #[test]
    fn nrr_converts() {
        convert("nrr", 0);
    }

    #[test]
    fn simplechain_converts() {
        for dir in [
            "simplechain/wrap0",
            "simplechain/wrap1",
            "simplechain/wrap2",
        ] {
            convert(dir, 1);
        }
    }

    #[test]
    fn tree_converts() {
        for dir in [
            "treeproofreturn/wrap0",
            "treeproofreturn/wrap1",
            "treeproofreturn/wrap2",
        ] {
            convert(dir, 2);
        }
    }
}
