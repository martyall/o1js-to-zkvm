//! Core (no_std) types for the out-of-circuit Pickles verifier, ported from
//! the PureScript `Pickles.Verify`. These are the inputs the verifier consumes;
//! the `std` `wire` module parses OCaml fixtures into them.
//!
//! Field/curve mapping (confirmed against the PS `StepField`/`WrapField`):
//!   * `StepField` = Tick = `Fp` (Vesta scalar / Pallas base)
//!   * `WrapField` = Tock = `Fq` (Pallas scalar / Vesta base)
//!   * the wrap proof + VK live over `Pallas`; the stage-2 accumulator MSM
//!     uses the `Vesta` SRS.

use alloc::vec::Vec;

use kimchi::circuits::berkeley_columns::{BerkeleyChallengeTerm, Column};
use kimchi::circuits::expr::{Linearization, PolishToken};
use kimchi::proof::{PointEvaluations, ProverProof};
use kimchi::verifier_index::VerifierIndex;
use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};
use mina_poseidon::pasta::FULL_ROUNDS;
use poly_commitment::ipa::OpeningProof;
use poly_commitment::OpenProof;

/// Step-proof field (Tick).
pub type StepField = Fp;
/// Wrap-proof field (Tock).
pub type WrapField = Fq;

/// The SRS the wrap `VerifierIndex` carries (`#[serde(skip)]`; attached at
/// conversion time).
pub type WrapSrs = <OpeningProof<Pallas, FULL_ROUNDS> as OpenProof<Pallas, FULL_ROUNDS>>::SRS;
/// The step (`Vesta`) SRS, for the stage-2 accumulator MSM.
pub type VestaSrs = <OpeningProof<Vesta, FULL_ROUNDS> as OpenProof<Vesta, FULL_ROUNDS>>::SRS;

/// `vk.serde.json` — the wrap proof's kimchi verifier index (over `Pallas`).
pub type WrapVerifierIndex = VerifierIndex<FULL_ROUNDS, Pallas, WrapSrs>;
/// `proof.serde.json` — the wrap kimchi proof (over `Pallas`).
pub type WrapProof = ProverProof<Pallas, OpeningProof<Pallas, FULL_ROUNDS>, FULL_ROUNDS>;

/// The step (Tick) linearization polynomial in kimchi Polish/RPN form, built
/// once via `expr_linearization::<StepField>(Some(&FeatureFlags::default()),
/// true)` — specialized to the step circuit's all-off feature flags, so it is
/// `SkipIf`-free and evaluable by kimchi's `PolishToken::evaluate` (whose
/// `FeatureFlag::is_enabled()` is `todo!()`). Evaluated for `ft_eval0`. PS
/// `LinearizationPoly StepField` (= `Pickles.Linearization.pallas`).
/// `index_terms` is empty (`expr_linearization` folds everything into
/// `constant_term`).
pub type StepLinearization =
    Linearization<Vec<PolishToken<StepField, Column, BerkeleyChallengeTerm>>, Column>;

/// Number of step IPA rounds (`StepIPARounds` = step SRS log2 = 16).
pub const STEP_IPA_ROUNDS: usize = 16;
/// Number of wrap IPA rounds (`WrapIPARounds` = 15).
pub const WRAP_IPA_ROUNDS: usize = 15;

/// Minimal Plonk deferred values: the raw 128-bit (pre-endo) challenges, as
/// field elements. Port of the PS `PlonkMinimal`.
#[derive(Debug, Clone)]
pub struct PlonkMinimal {
    pub alpha: StepField,
    pub beta: StepField,
    pub gamma: StepField,
    pub zeta: StepField,
}

/// `branch_data` — the proofs-verified prefix mask (CONSTANT `to_bool_vec`
/// encoding: N0=[F,F], N1=[F,T], N2=[T,T]) plus the step domain log2.
#[derive(Debug, Clone)]
pub struct BranchData {
    pub domain_log2: StepField,
    pub proofs_verified_mask: [bool; 2],
}

/// `prev_evals` — the previous (step) proof's evaluations, natively chunked
/// (one `zeta`/`zeta_omega` per num_chunks). Port of the PS `ChunkedAllEvals`.
#[derive(Debug, Clone)]
pub struct ChunkedAllEvals {
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

/// Per-tag verifier constants (`Pickles.Verify.Verifier` / `mkVerifier`). Built
/// once from the wrap VK + SRSes; reused across every proof of a tag.
pub struct Verifier {
    /// wrap proof's kimchi verifier index (`Pallas`), SRS attached.
    pub wrap_vk: WrapVerifierIndex,
    /// step (`Vesta`) SRS, for the stage-2 accumulator `compute_sg` MSM.
    pub vesta_srs: VestaSrs,
    /// step domain log2 (`stepProverIndex.domain.log_size_of_group`).
    pub step_domain_log2: usize,
    /// kimchi `zkRows` (`Pickles.Constants.zkRows` = `(16·nc + 5) / 7`).
    pub step_zk_rows: usize,
    /// step SRS size log2 (cycle constant `= STEP_IPA_ROUNDS = 16`).
    pub step_srs_length_log2: usize,
    /// step domain generator `omega`.
    pub step_generator: StepField,
    /// permutation shifts for the step domain.
    pub step_shifts: [StepField; 7],
    /// step-field scalar endo coefficient.
    pub step_endo: StepField,
    /// step (`ft_eval0`) linearization polynomial, consumed by stage 1 via the
    /// kimchi `PolishToken` evaluator. PS `Verifier.linearizationPoly`.
    pub linearization: StepLinearization,
}

/// The minimal data the verifier reads for one proof
/// (`Pickles.Verify.VerifiableProof`). The 9 carried fields come straight from
/// the wire; the 3 recomputed ones (`old_bulletproof_challenges` + the two
/// message digests) are produced by the conversion.
pub struct VerifiableProof {
    pub wrap_proof: WrapProof,
    pub raw_plonk: PlonkMinimal,
    /// the proof's own 16-round raw (pre-endo) bp challenges.
    pub raw_bulletproof_challenges: [StepField; STEP_IPA_ROUNDS],
    pub branch_data: BranchData,
    pub sponge_digest_before_evaluations: StepField,
    pub prev_evals: ChunkedAllEvals,
    pub p_eval0_chunks: Vec<StepField>,
    /// previous-proof bp challenges, ALREADY endo-expanded (length `mpv`).
    pub old_bulletproof_challenges: Vec<[StepField; STEP_IPA_ROUNDS]>,
    /// the proof's own wrap challenge-polynomial commitment (`Vesta`).
    pub challenge_polynomial_commitment: Vesta,
    pub messages_for_next_step_proof_digest: StepField,
    pub messages_for_next_wrap_proof_digest: WrapField,
    pub step_domain_log2: usize,
}
