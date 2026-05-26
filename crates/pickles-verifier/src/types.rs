//! Core (no_std) types for the out-of-circuit Pickles verifier — the inputs
//! the verifier consumes. The `std` `wire` module parses OCaml fixtures into
//! these.
//!
//! Field/curve mapping:
//!   * `StepField` = Tick = `Fp` (Vesta scalar / Pallas base)
//!   * `WrapField` = Tock = `Fq` (Pallas scalar / Vesta base)
//!   * the wrap proof + VK live over `Pallas`; the stage-2 accumulator MSM
//!     uses the `Vesta` SRS.

use alloc::sync::Arc;
use alloc::vec::Vec;

use kimchi::alphas::Alphas;
use kimchi::circuits::berkeley_columns::{BerkeleyChallengeTerm, Column};
use kimchi::circuits::constraints::FeatureFlags;
use kimchi::circuits::expr::{Linearization, PolishToken};
use kimchi::linearization::expr_linearization;
use kimchi::proof::{PointEvaluations, ProverProof};
use kimchi::verifier_index::VerifierIndex;
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use mina_poseidon::pasta::FULL_ROUNDS;
use o1_utils::serialization::SerdeAs;
use poly_commitment::ipa::{endos, OpeningProof};
use poly_commitment::OpenProof;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Step-proof field (Tick).
pub type StepField = Fp;
/// Wrap-proof field (Tock).
pub type WrapField = Fq;

/// The Pallas SRS the wrap `VerifierIndex` carries (`#[serde(skip)]`; attached
/// at conversion time).
pub type WrapSrs = <OpeningProof<Pallas, FULL_ROUNDS> as OpenProof<Pallas, FULL_ROUNDS>>::SRS;
/// The step (Vesta) SRS, used for the stage-2 accumulator MSM.
pub type VestaSrs = <OpeningProof<Vesta, FULL_ROUNDS> as OpenProof<Vesta, FULL_ROUNDS>>::SRS;

/// `vk.serde.json` — the wrap proof's kimchi verifier index (over `Pallas`).
pub type WrapVerifierIndex = VerifierIndex<FULL_ROUNDS, Pallas, WrapSrs>;
/// `proof.serde.json` — the wrap kimchi proof (over `Pallas`).
pub type WrapProof = ProverProof<Pallas, OpeningProof<Pallas, FULL_ROUNDS>, FULL_ROUNDS>;

/// The step (Tick) linearization polynomial in kimchi Polish/RPN form. Built
/// once via `expr_linearization::<StepField>(Some(&FeatureFlags::default()),
/// true)` — specialized to the step circuit's all-off feature flags so it is
/// `SkipIf`-free and evaluable by kimchi's `PolishToken::evaluate` (whose
/// `FeatureFlag::is_enabled()` is `todo!()`). Evaluated for `ft_eval0`.
/// `index_terms` is empty (everything folds into `constant_term`).
pub type StepLinearization =
    Linearization<Vec<PolishToken<StepField, Column, BerkeleyChallengeTerm>>, Column>;

/// Number of step IPA rounds (= step SRS log2).
pub const STEP_IPA_ROUNDS: usize = 16;
/// Number of wrap IPA rounds.
pub const WRAP_IPA_ROUNDS: usize = 15;

/// Minimal Plonk deferred values: the raw 128-bit (pre-endo) challenges as
/// field elements.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlonkMinimal {
    #[serde_as(as = "SerdeAs")]
    pub alpha: StepField,
    #[serde_as(as = "SerdeAs")]
    pub beta: StepField,
    #[serde_as(as = "SerdeAs")]
    pub gamma: StepField,
    #[serde_as(as = "SerdeAs")]
    pub zeta: StepField,
}

/// `branch_data` — the proofs-verified prefix mask (CONSTANT `to_bool_vec`
/// encoding: N0 = `[F,F]`, N1 = `[F,T]`, N2 = `[T,T]`) plus the step domain
/// log2.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchData {
    #[serde_as(as = "SerdeAs")]
    pub domain_log2: StepField,
    pub proofs_verified_mask: [bool; 2],
}

/// `prev_evals` — the previous (step) proof's evaluations, natively chunked
/// (one `zeta`/`zeta_omega` per num_chunks).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkedAllEvals {
    #[serde_as(as = "SerdeAs")]
    pub ft_eval1: StepField,
    /// public-input poly eval — a single chunk (flat `[zeta, omega]`).
    pub public_evals: PointEvaluations<Vec<StepField>>,
    pub z: PointEvaluations<Vec<StepField>>,
    pub w: [PointEvaluations<Vec<StepField>>; 15],
    pub coefficients: [PointEvaluations<Vec<StepField>>; 15],
    pub s: [PointEvaluations<Vec<StepField>>; 6],
    /// index selectors: generic, poseidon, complete_add, mul, emul, endomul_scalar.
    pub index: [PointEvaluations<Vec<StepField>>; 6],
}

/// Per-tag verifier constants. Built once from the wrap VK + SRSes and reused
/// across every proof of a tag.
pub struct Verifier {
    /// wrap proof's kimchi verifier index (`Pallas`), SRS attached.
    pub wrap_vk: WrapVerifierIndex,
    /// step (`Vesta`) SRS, for the stage-2 accumulator `compute_sg` MSM. Shared
    /// via `Arc` so a single SRS can back many tags / proofs.
    pub vesta_srs: Arc<VestaSrs>,
    /// kimchi `zkRows` = `(16·nc + 5) / 7`.
    pub step_zk_rows: usize,
    /// step SRS size log2 (cycle constant = [`STEP_IPA_ROUNDS`]).
    pub step_srs_length_log2: usize,
    /// step-field scalar endo coefficient.
    pub step_endo: StepField,
    /// step (`ft_eval0`) linearization polynomial, consumed by stage 1 via the
    /// kimchi `PolishToken` evaluator.
    pub linearization: StepLinearization,
    /// powers-of-alpha map produced alongside the linearization by
    /// `expr_linearization`. Stage 1's `ft_eval0` and `derive_plonk` permutation
    /// term need the instantiated `Permutation` alphas
    /// (`get_alphas(Permutation, …)`), which the linearization alone drops.
    pub powers_of_alpha: Alphas<StepField>,
}

impl Verifier {
    /// Build the per-tag verifier. `step_zk_rows` comes from `num_chunks`
    /// (`(16·nc + 5) / 7`); the step SRS length log2 is the protocol-fixed
    /// [`STEP_IPA_ROUNDS`]; the step linearization is the Tick polynomial
    /// specialized to the step circuit's (all-off) feature flags, so it is
    /// `SkipIf`-free and kimchi's `PolishToken::evaluate` consumes it
    /// directly. The wrap VK is reconstructed: its serde form
    /// `#[serde(skip)]`s `srs`, `linearization`, `powers_of_alpha`, AND
    /// `endo`. The endo is the Vesta *base* endo (`endos::<Vesta>().0`,
    /// matching kimchi's `pasta_fq_plonk_verifier_index` OCaml stub), NOT the
    /// deserialized default (zero), which would zero out the endomul-gate
    /// terms in `ft_eval0`. The lazy `OnceCell`s (`w`,
    /// `permutation_vanishing_polynomial_m`) recompute correctly for the nc=1
    /// wrap circuit.
    ///
    /// `wrap_srs` and `vesta_srs` are passed as `Arc`s so one SRS per curve
    /// can back many tags / proofs.
    ///
    /// `no_std` so the SP1 guest can assemble its `Verifier` from a
    /// deserialized wrap VK + pod-cast SRSes.
    pub fn new(
        wrap_vk: WrapVerifierIndex,
        wrap_srs: Arc<WrapSrs>,
        vesta_srs: Arc<VestaSrs>,
        step_num_chunks: usize,
    ) -> Verifier {
        let mut wrap_vk = wrap_vk;
        wrap_vk.srs = wrap_srs;
        let (wrap_lin, wrap_alphas) =
            expr_linearization::<WrapField>(Some(&FeatureFlags::default()), true);
        wrap_vk.linearization = wrap_lin;
        wrap_vk.powers_of_alpha = wrap_alphas;
        wrap_vk.endo = endos::<Vesta>().0;
        let (linearization, powers_of_alpha) =
            expr_linearization::<StepField>(Some(&FeatureFlags::default()), true);
        Verifier {
            wrap_vk,
            vesta_srs,
            step_zk_rows: (16 * step_num_chunks + 5) / 7,
            step_srs_length_log2: STEP_IPA_ROUNDS,
            step_endo: endos::<Vesta>().1,
            linearization,
            powers_of_alpha,
        }
    }
}

/// The minimal data the verifier reads for one proof. The 9 carried fields
/// come straight from the wire; the 3 recomputed ones
/// (`old_bulletproof_challenges` + the two message digests) are produced by
/// the conversion.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct VerifiableProof {
    pub wrap_proof: WrapProof,
    pub raw_plonk: PlonkMinimal,
    /// the proof's own 16-round raw (pre-endo) bp challenges.
    #[serde_as(as = "[SerdeAs; STEP_IPA_ROUNDS]")]
    pub raw_bulletproof_challenges: [StepField; STEP_IPA_ROUNDS],
    pub branch_data: BranchData,
    #[serde_as(as = "SerdeAs")]
    pub sponge_digest_before_evaluations: StepField,
    pub prev_evals: ChunkedAllEvals,
    #[serde_as(as = "Vec<SerdeAs>")]
    pub p_eval0_chunks: Vec<StepField>,
    /// previous-proof bp challenges, ALREADY endo-expanded (length `mpv`).
    #[serde_as(as = "Vec<[SerdeAs; STEP_IPA_ROUNDS]>")]
    pub old_bulletproof_challenges: Vec<[StepField; STEP_IPA_ROUNDS]>,
    /// the proof's own wrap challenge-polynomial commitment (`Vesta`).
    #[serde_as(as = "SerdeAs")]
    pub challenge_polynomial_commitment: Vesta,
    #[serde_as(as = "SerdeAs")]
    pub messages_for_next_step_proof_digest: StepField,
    #[serde_as(as = "SerdeAs")]
    pub messages_for_next_wrap_proof_digest: WrapField,
    pub step_domain_log2: usize,
}
