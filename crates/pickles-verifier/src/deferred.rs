//! Stage 1 of the out-of-circuit Pickles verifier: expand the wrap proof's
//! carried minimal skeleton into the full deferred values.
//!
//! The heavy lifting — replaying the inner step proof's Fr-sponge to recover
//! `xi`/`r`, and computing `ft_eval0` via the linearization interpreter — is
//! delegated to kimchi's [`oracles_from_digest`] (the extracted post-digest
//! tail of `ProverProof::oracles`). The pickles-specific glue layered on top:
//!
//!   * **combined inner product** — base-column CIP via the
//!     `combined_inner_product` leaf (features off ⇒ no optional-gate/lookup
//!     columns);
//!   * **`derive_plonk`** — the Type1 plonk scalars (`perm` via
//!     `ConstraintSystem::perm_scalars`, `zeta_to_domain_size`,
//!     `zeta_to_srs_length`);
//!   * **bulletproof challenges + b** — endo-expand the raw prechallenges and
//!     evaluate `b_poly(zeta) + r·b_poly(zetaw)`.
//!
//! Output is [`ExpandedDeferredValues`], the RAW (pre-Type1-shift,
//! pre-cross-field) scalar values. The Type1 shift, cross-field
//! reinterpretation, and flattening into the wrap kimchi public input is the
//! next stage (the bridge to the stage-3 dlog check) and is NOT done here.

use alloc::vec::Vec;

use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use kimchi::circuits::argument::ArgumentType;
use kimchi::circuits::constraints::ConstraintSystem;
use kimchi::circuits::polynomials::permutation;
use kimchi::proof::{PointEvaluations, ProofEvaluations, RecursionChallenge};
use kimchi::verifier::{oracles_from_digest, DigestOracles};
use mina_curves::pasta::{Pallas, Vesta};
use mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use mina_poseidon::pasta::FULL_ROUNDS;
use mina_poseidon::sponge::{DefaultFrSponge, ScalarChallenge};
use poly_commitment::commitment::{b_poly, combined_inner_product, PolyComm};
use poly_commitment::ipa::endos;

use crate::types::{BranchData, ChunkedAllEvals, StepField, VerifiableProof, Verifier, WrapField};

/// Fr-sponge over the step field (`Fp`), matching kimchi's `DefaultFrSponge` for
/// `Vesta` (the step curve). `oracles_from_digest` instantiates this internally
/// from `Vesta::sponge_params()`.
type StepFrSponge = DefaultFrSponge<StepField, PlonkSpongeConstantsKimchi, FULL_ROUNDS>;

/// The expanded wrap deferred values (RAW scalars, pre-Type1-shift) — the
/// subset of the wrap `DeferredValuesOutput` consumed by the stage-1 → stage-3
/// bridge.
#[derive(Debug, Clone)]
pub struct ExpandedDeferredValues {
    // ----- plonk scalars (derived in `derive_plonk`) -----
    /// raw 128-bit `alpha` (carried, NOT endo-expanded).
    pub alpha: StepField,
    /// raw 128-bit `beta`.
    pub beta: StepField,
    /// raw 128-bit `gamma`.
    pub gamma: StepField,
    /// raw 128-bit `zeta` (carried).
    pub zeta: StepField,
    /// permutation scalar (`ConstraintSystem::perm_scalars`).
    pub perm: StepField,
    /// `zeta^(2^domain_log2)` (= `zeta1`).
    pub zeta_to_domain_size: StepField,
    /// `zeta^(2^srs_length_log2)`.
    pub zeta_to_srs_length: StepField,

    // ----- combined inner product -----
    /// the batched `combined_inner_product` (= `xi`-folded evaluations).
    pub combined_inner_product: StepField,

    // ----- bulletproof -----
    /// the `xi` polyscale challenge (raw `ScalarChallenge`, = the Fr-sponge `v`).
    pub xi: ScalarChallenge<StepField>,
    /// the raw 16-round prechallenges (carried, pre-endo).
    pub bulletproof_prechallenges: [StepField; 16],
    /// the IPA opening target `b = b_poly(zeta) + r·b_poly(zetaw)`.
    pub b: StepField,
    /// the endo-expanded new bulletproof challenges.
    pub new_bulletproof_challenges: [StepField; 16],

    // ----- carried / oracle echoes -----
    pub branch_data: BranchData,
    /// collapsed public-input poly evaluation (`x_hat`) at `(zeta, zeta·omega)`.
    pub x_hat_eval: PointEvaluations<StepField>,
    pub sponge_digest_before_evaluations: StepField,
    /// the `r` evalscale challenge field value (= the Fr-sponge `u`).
    pub r: StepField,
    /// the step `ft_eval0` (from the linearization interpreter).
    pub ft_eval0: StepField,
}

/// Convert the carried `ChunkedAllEvals` (the inner step proof's evaluations)
/// into a kimchi `ProofEvaluations`. The step circuits have all feature flags
/// off, so every optional gate / lookup evaluation is `None`.
fn to_proof_evaluations(e: &ChunkedAllEvals) -> ProofEvaluations<PointEvaluations<Vec<StepField>>> {
    ProofEvaluations {
        public: Some(e.public_evals.clone()),
        w: e.w.clone(),
        z: e.z.clone(),
        s: e.s.clone(),
        coefficients: e.coefficients.clone(),
        generic_selector: e.index[0].clone(),
        poseidon_selector: e.index[1].clone(),
        complete_add_selector: e.index[2].clone(),
        mul_selector: e.index[3].clone(),
        emul_selector: e.index[4].clone(),
        endomul_scalar_selector: e.index[5].clone(),
        range_check0_selector: None,
        range_check1_selector: None,
        foreign_field_add_selector: None,
        foreign_field_mul_selector: None,
        xor_selector: None,
        rot_selector: None,
        lookup_aggregation: None,
        lookup_table: None,
        lookup_sorted: [None, None, None, None, None],
        runtime_lookup_table: None,
        runtime_lookup_table_selector: None,
        xor_lookup_selector: None,
        lookup_gate_lookup_selector: None,
        range_check_lookup_selector: None,
        foreign_field_mul_lookup_selector: None,
    }
}

/// Stage 1 — reconstruct the wrap deferred values from the carried skeleton.
///
/// # Panics
///
/// Panics only on a malformed step domain log2 (no radix-2 domain of that size),
/// unreachable for valid step circuits.
pub fn expand_deferred(verifier: &Verifier, proof: &VerifiableProof) -> ExpandedDeferredValues {
    // The scalar endo (`endos::<Vesta>().1`) — used to endo-expand the
    // 128-bit challenges via `ScalarChallenge::to_field`.
    let endo = verifier.step_endo;
    // The gate (base) endo — `ft_eval0`'s `Constants.endo_coefficient` for the
    // endomul gate constraints. The step (Vesta) VK uses `endos::<Pallas>().0`
    // (kimchi OCaml stub `pasta_fp_plonk_verifier_index`), NOT the scalar endo.
    // (nrr's step has no endomul-gate contribution, so its endo was masked; the
    // recursive simple_chain/tree step circuits exercise it.) Two distinct endo
    // coefficients, two distinct uses.
    let gate_endo = endos::<Pallas>().0;

    // The proof's OWN step domain: multi-branch compiled outputs share one
    // `Verifier` whose `step_domain_log2`/generator/shifts are the first
    // branch's, so re-expansion must use this proof's branch's domain.
    let domain_log2 = proof.step_domain_log2;
    let domain = Radix2EvaluationDomain::<StepField>::new(1usize << domain_log2)
        .unwrap_or_else(|| panic!("no radix-2 domain of size 2^{domain_log2}"));
    let generator = domain.group_gen;
    let max_poly_size = 1usize << verifier.step_srs_length_log2;
    let zk_rows = verifier.step_zk_rows as u64;
    let shifts: [StepField; 7] = *permutation::Shifts::new(&domain).shifts();

    // The step proof's evaluations + previous-recursion challenges. The
    // bp-polynomial values come from `chals`; the `comm` field is unused on
    // this path (`RecursionChallenge::evals` ignores it, and the CIP reads
    // only the evaluation values) but kimchi's type requires one — pass a
    // dummy.
    let step_evals = to_proof_evaluations(&proof.prev_evals);
    let prev_challenges: Vec<RecursionChallenge<Vesta>> = proof
        .old_bulletproof_challenges
        .iter()
        .map(|chals| RecursionChallenge {
            chals: chals.to_vec(),
            comm: PolyComm {
                chunks: alloc::vec![<Vesta as ark_ec::AffineRepr>::zero()],
            },
        })
        .collect();

    // Carried challenges: alpha + zeta are endo-expanded; beta + gamma stay raw
    // (matches kimchi's `oracles`: alpha/zeta = `to_field(endo)`, beta/gamma =
    // raw sponge challenges).
    let alpha_chal = ScalarChallenge::new(proof.raw_plonk.alpha);
    let zeta_chal = ScalarChallenge::new(proof.raw_plonk.zeta);
    let alpha = alpha_chal.to_field(&endo);
    let beta = proof.raw_plonk.beta;
    let gamma = proof.raw_plonk.gamma;
    let zeta = zeta_chal.to_field(&endo);

    let DigestOracles {
        oracles,
        all_alphas,
        public_evals,
        powers_of_eval_points_for_chunks,
        polys,
        zeta1,
        ft_eval0,
        ..
    } = oracles_from_digest::<FULL_ROUNDS, Vesta, StepFrSponge>(
        domain,
        max_poly_size,
        zk_rows,
        &shifts,
        gate_endo,
        &verifier.linearization,
        &verifier.powers_of_alpha,
        proof.sponge_digest_before_evaluations,
        alpha,
        beta,
        gamma,
        zeta,
        alpha_chal,
        zeta_chal,
        None,
        &prev_challenges,
        &step_evals,
        proof.prev_evals.ft_eval1,
        None,
    )
    .expect("oracles_from_digest");

    let xi = oracles.v; // polyscale
    let r = oracles.u; // evalscale
    let zetaw = zeta * generator;

    // ----- combined inner product (base columns, features off) -----
    // Build the per-polynomial evaluation table exactly as kimchi's `oracles`
    // CIP block does (minus the optional-gate / lookup chains, all absent here):
    // bp_polys, public_input, ft, z, the 6 index selectors, 15 witness, 15
    // coefficient, 6 sigma. Each entry is `[zeta_chunks, zeta_omega_chunks]`.
    let pe =
        |p: &PointEvaluations<Vec<StepField>>| alloc::vec![p.zeta.clone(), p.zeta_omega.clone()];
    let mut es: Vec<Vec<Vec<StepField>>> = polys.iter().map(|(_, e)| e.clone()).collect();
    es.push(public_evals.to_vec());
    es.push(alloc::vec![
        alloc::vec![ft_eval0],
        alloc::vec![proof.prev_evals.ft_eval1]
    ]);
    es.push(pe(&step_evals.z));
    es.push(pe(&step_evals.generic_selector));
    es.push(pe(&step_evals.poseidon_selector));
    es.push(pe(&step_evals.complete_add_selector));
    es.push(pe(&step_evals.mul_selector));
    es.push(pe(&step_evals.emul_selector));
    es.push(pe(&step_evals.endomul_scalar_selector));
    for w in &step_evals.w {
        es.push(pe(w));
    }
    for c in &step_evals.coefficients {
        es.push(pe(c));
    }
    for s in &step_evals.s {
        es.push(pe(s));
    }
    let cip = combined_inner_product(&xi, &r, &es);

    // ----- derive_plonk (Type1 scalars) -----
    let collapsed = step_evals.combine(&powers_of_eval_points_for_chunks);
    // `derive_plonk` zk_polynomial: 3-factor product over the last zk rows,
    // evaluated at the endo-expanded zeta.
    let omega_inv = generator.inverse().expect("generator nonzero");
    let omega_to_minus_zk_rows = omega_inv.pow([zk_rows]);
    let omega_to_zk_plus_1 = omega_inv.pow([zk_rows - 1]);
    let zk_polynomial =
        (zeta - omega_inv) * (zeta - omega_to_zk_plus_1) * (zeta - omega_to_minus_zk_rows);
    let perm = ConstraintSystem::<StepField>::perm_scalars(
        &collapsed,
        beta,
        gamma,
        all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS),
        zk_polynomial,
    );
    let zeta_to_domain_size = zeta1;
    let zeta_to_srs_length = powers_of_eval_points_for_chunks.zeta;

    // ----- bulletproof challenges + b -----
    let new_chals: Vec<StepField> = proof
        .raw_bulletproof_challenges
        .iter()
        .map(|c| ScalarChallenge::new(*c).to_field(&endo))
        .collect();
    let b = b_poly(&new_chals, zeta) + r * b_poly(&new_chals, zetaw);
    let new_bulletproof_challenges: [StepField; 16] = new_chals
        .try_into()
        .unwrap_or_else(|_| unreachable!("exactly 16 bp challenges"));

    let x_hat = collapsed.public.expect("public eval present");

    ExpandedDeferredValues {
        alpha: proof.raw_plonk.alpha,
        beta: proof.raw_plonk.beta,
        gamma: proof.raw_plonk.gamma,
        zeta: proof.raw_plonk.zeta,
        perm,
        zeta_to_domain_size,
        zeta_to_srs_length,
        combined_inner_product: cip,
        xi: oracles.v_chal,
        bulletproof_prechallenges: proof.raw_bulletproof_challenges,
        b,
        new_bulletproof_challenges,
        branch_data: proof.branch_data.clone(),
        x_hat_eval: x_hat,
        sponge_digest_before_evaluations: proof.sponge_digest_before_evaluations,
        r,
        ft_eval0,
    }
}

// ---------------------------------------------------------------------------
// Stage-1 → stage-3 bridge: assemble the wrap kimchi public input
// (`Wrap.StatementPacked.value_to_fields`).
// ---------------------------------------------------------------------------

/// Reinterpret a step-field element's canonical integer in the wrap field
/// (mod-reducing). Exact for the values it is used on here — digests and
/// 128-bit challenges, all `<` both
/// Pasta moduli — and the post-shift representative in the Type1 conversion.
fn fp_to_fq(x: StepField) -> WrapField {
    WrapField::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le())
}

/// Cross-field Type1 of a RAW (unshifted) step-field scalar, as the wrap
/// statement stores it: applying `to_shifted (from_shifted t)` un-shifts the
/// stored same-field `Type1`, recovering the raw
/// value, then the cross-field `toShifted` reshifts. We store raw, so we apply
/// the cross-field `toShifted` directly: compute `(raw − (2^255+1)) / 2` in the
/// STEP field, then reinterpret that integer in the wrap field
/// (`Shifted (F Vesta::ScalarField) (Type1 (F Vesta::BaseField))`).
fn cross_field_type1(raw: StepField) -> WrapField {
    // `shift1` for the step field (255-bit): c = 2^255 + 1, scale = 1/2.
    let c = StepField::from(2u64).pow([255u64]) + StepField::one();
    let scale = StepField::from(2u64).inverse().expect("2 is invertible");
    fp_to_fq((raw - c) * scale)
}

/// `Branch_data.pack`: `4·domain_log2 + m0 + 2·m1`.
fn pack_branch_data(bd: &BranchData) -> WrapField {
    let bit = |b: bool| {
        if b {
            WrapField::one()
        } else {
            WrapField::zero()
        }
    };
    let log2w = fp_to_fq(bd.domain_log2);
    WrapField::from(4u64) * log2w
        + bit(bd.proofs_verified_mask[0])
        + WrapField::from(2u64) * bit(bd.proofs_verified_mask[1])
}

/// Flatten the expanded deferred values + the two message digests into the wrap
/// proof's kimchi public input (40 `WrapField` elements). Mirrors PS
/// `assembleWrapMainInput` + the `Wrap.StatementPacked` `valueToFields` order:
/// 5 Type1 fp fields, 2 challenges, 3 scalar challenges, 3 digests, 16
/// bulletproof challenges, 1 packed branch_data, 8 feature-flag + 2 lookup slots
/// (all zero, features off).
pub fn wrap_public_input(
    dv: &ExpandedDeferredValues,
    messages_for_next_step_proof_digest: StepField,
    messages_for_next_wrap_proof_digest: WrapField,
) -> Vec<WrapField> {
    let mut pi = Vec::with_capacity(40);

    // 5 Type1 fp fields: combined_inner_product, b, zeta_to_srs_length,
    // zeta_to_domain_size, perm.
    pi.push(cross_field_type1(dv.combined_inner_product));
    pi.push(cross_field_type1(dv.b));
    pi.push(cross_field_type1(dv.zeta_to_srs_length));
    pi.push(cross_field_type1(dv.zeta_to_domain_size));
    pi.push(cross_field_type1(dv.perm));

    // 2 challenges (raw 128-bit, reinterpreted): beta, gamma.
    pi.push(fp_to_fq(dv.beta));
    pi.push(fp_to_fq(dv.gamma));

    // 3 scalar challenges: alpha, zeta, xi.
    pi.push(fp_to_fq(dv.alpha));
    pi.push(fp_to_fq(dv.zeta));
    pi.push(fp_to_fq(dv.xi.inner()));

    // 3 digests: sponge_digest (cross), msg_for_next_wrap (already wrap),
    // msg_for_next_step (cross).
    pi.push(fp_to_fq(dv.sponge_digest_before_evaluations));
    pi.push(messages_for_next_wrap_proof_digest);
    pi.push(fp_to_fq(messages_for_next_step_proof_digest));

    // 16 bulletproof prechallenges (raw 128-bit, reinterpreted).
    for c in &dv.bulletproof_prechallenges {
        pi.push(fp_to_fq(*c));
    }

    // 1 packed branch_data.
    pi.push(pack_branch_data(&dv.branch_data));

    // 8 feature-flag slots + lookup flag + lookup scalar challenge (all zero).
    pi.resize(pi.len() + 10, WrapField::zero());

    pi
}
