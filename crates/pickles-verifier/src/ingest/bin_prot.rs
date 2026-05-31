//! Decode the bin_prot wire form of a Mina blockchain SNARK (a.k.a. wrap
//! pickles proof) into the crate's canonical [`VerifiableProof`].
//!
//! The bytes this module consumes are what the Mina daemon's GraphQL serves
//! at `bestChain[0].protocolStateProof.base64` (after URL-safe base64 decode),
//! and what o1js's `Proof.toJSON()` embeds inside its `proof` string. Both
//! upstreams produce the same OCaml `Pickles.Proof.t` bin_prot encoding;
//! `mina_p2p_messages::v2::MinaBaseProofStableV2` is the Rust mirror.
//!
//! The strategy: build an [`OcamlProof`] from the parsed bin_prot mirror, then
//! reuse the existing [`OcamlProof::into_verifiable`] to fold in the wrap VK
//! + app statement and produce the canonical [`VerifiableProof`]. The mapping
//! is exactly what `parse_*` in [`crate::wire`] does for the JSON skeleton —
//! only the source representation differs.
//!
//! The wrap kimchi `ProverProof` reconstruction from bin_prot
//! ([`to_wrap_proof`]) is the load-bearing piece; everything else is
//! straightforward field copies + endianness handling.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use binprot::BinProtRead;
use kimchi::proof::{
    PointEvaluations, ProofEvaluations, ProverCommitments, ProverProof, RecursionChallenge,
};
use mina_curves::pasta::{Pallas, Vesta};
use mina_p2p_messages::v2::{
    MinaBaseProofStableV2, PicklesProofProofsVerified2ReprStableV2,
    PicklesProofProofsVerified2ReprStableV2PrevEvalsEvalsEvals, PicklesWrapWireProofStableV1,
    PicklesReducedMessagesForNextProofOverSameFieldWrapChallengesVectorStableV2AChallenge,
};
use mina_poseidon::sponge::ScalarChallenge;
use o1_utils::FieldHelpers;
use poly_commitment::commitment::PolyComm;
use poly_commitment::ipa::{endos, OpeningProof};

use crate::types::{
    BranchData, ChunkedAllEvals, PlonkMinimal, StepField, VerifiableProof, WrapField,
    WrapProof, WrapVerifierIndex, STEP_IPA_ROUNDS, WRAP_IPA_ROUNDS,
};
use crate::wire::OcamlProof;

/// Decode raw bin_prot bytes into the `mina_p2p_messages` mirror.
///
/// If this fails, the upstream's bin_prot stable-version layout differs from
/// what the openmina pin we use expects — that's the failure mode worth
/// recording in SUMMARY.md.
pub fn decode_bytes(bytes: &[u8]) -> Result<MinaBaseProofStableV2, binprot::Error> {
    MinaBaseProofStableV2::binprot_read(&mut &*bytes)
}

/// All-in-one: decode bin_prot bytes, build the canonical [`VerifiableProof`].
///
/// `wrap_vk` is the blockchain SNARK's wrap verification key (a per-network
/// constant — pickled into the daemon's `blockchainVerificationKey` GraphQL
/// field, baked into the `mainnet-blockchain-snark` fixture for o1js-to-zkvm).
/// `app_state` is the application statement field encoding — for a blockchain
/// SNARK this is `[protocol_state_hash]`.
pub fn to_verifiable_proof(
    bytes: &[u8],
    wrap_vk: &WrapVerifierIndex,
    app_state: &[StepField],
) -> Result<VerifiableProof, ConvertError> {
    let parsed = decode_bytes(bytes).map_err(|e| ConvertError::BinProt(e.to_string()))?;
    let ocaml = ocaml_proof_from_bin_prot(&parsed.0)?;
    let wrap = to_wrap_proof(&parsed.0)?;
    ocaml
        .into_verifiable(wrap, wrap_vk, app_state)
        .map_err(ConvertError::Convert)
}

#[derive(Debug)]
pub enum ConvertError {
    BinProt(String),
    Field(String),
    Convert(String),
}

impl core::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConvertError::BinProt(e) => write!(f, "bin_prot decode: {e}"),
            ConvertError::Field(e) => write!(f, "field reconstruction: {e}"),
            ConvertError::Convert(e) => write!(f, "OcamlProof::into_verifiable: {e}"),
        }
    }
}

impl std::error::Error for ConvertError {}

// ---------------------------------------------------------------------------
// BigInt / limb / challenge / curve-point helpers
// ---------------------------------------------------------------------------

/// `mina_p2p_messages::bigint::BigInt` is a 32-byte little-endian field
/// element. Reconstruct an arkworks-0.5 prime-field element via the workspace
/// `o1_utils::FieldHelpers::from_bytes` (which is also LE + range-checked).
fn bigint_to_field<F: ark_ff::PrimeField>(
    bi: &mina_p2p_messages::bigint::BigInt,
) -> Result<F, ConvertError> {
    F::from_bytes(bi.as_ref())
        .map_err(|e| ConvertError::Field(format!("BigInt → field: {e:?}")))
}

/// `(BigInt, BigInt)` (x, y) → affine point on the chosen curve.
/// `new_unchecked` matches the existing `wire::affine` behavior — on-curve
/// validation happens later in the verify path.
fn point_to_pallas(
    p: &(mina_p2p_messages::bigint::BigInt, mina_p2p_messages::bigint::BigInt),
) -> Result<Pallas, ConvertError> {
    Ok(Pallas::new_unchecked(
        bigint_to_field::<StepField>(&p.0)?,
        bigint_to_field::<StepField>(&p.1)?,
    ))
}
fn point_to_vesta(
    p: &(mina_p2p_messages::bigint::BigInt, mina_p2p_messages::bigint::BigInt),
) -> Result<Vesta, ConvertError> {
    Ok(Vesta::new_unchecked(
        bigint_to_field::<WrapField>(&p.0)?,
        bigint_to_field::<WrapField>(&p.1)?,
    ))
}

/// Combine a slice of OCaml `Hex64` LE limbs (`UInt64`) into a field element.
fn limbs_to_field<F: ark_ff::PrimeField>(
    limbs: &[mina_p2p_messages::v2::LimbVectorConstantHex64StableV1],
) -> Result<F, ConvertError> {
    let mut le = Vec::with_capacity(limbs.len() * 8);
    for l in limbs {
        let u: u64 = l.0 .0; // UInt64 newtype, inner u64
        le.extend_from_slice(&u.to_le_bytes());
    }
    // Pad to field byte size (the limbs may be shorter for 128-bit challenges).
    le.resize(F::size_in_bytes(), 0);
    F::from_bytes(&le)
        .map_err(|e| ConvertError::Field(format!("limbs → field: {e:?}")))
}

/// Both `alpha`/`zeta` (wrapped in `.inner`) and `beta`/`gamma` (already a
/// `PaddedSeq<u64, 2>`) decode through the same LE-limb path. This adapter
/// handles the wrapper.
fn ach_to_field<F: ark_ff::PrimeField>(
    a: &PicklesReducedMessagesForNextProofOverSameFieldWrapChallengesVectorStableV2AChallenge,
) -> Result<F, ConvertError> {
    limbs_to_field::<F>(&a.inner.0)
}

// ---------------------------------------------------------------------------
// OcamlProof construction (mirrors wire::OcamlProof::parse)
// ---------------------------------------------------------------------------

fn ocaml_proof_from_bin_prot(
    p: &PicklesProofProofsVerified2ReprStableV2,
) -> Result<OcamlProof, ConvertError> {
    let st = &p.statement;
    let dv = &st.proof_state.deferred_values;
    let msg_step = &st.messages_for_next_step_proof;
    let msg_wrap = &st.proof_state.messages_for_next_wrap_proof;

    // raw_plonk: 128-bit challenges as field elements (LE).
    let raw_plonk = PlonkMinimal {
        alpha: ach_to_field::<StepField>(&dv.plonk.alpha)?,
        beta: limbs_to_field::<StepField>(&dv.plonk.beta.0)?,
        gamma: limbs_to_field::<StepField>(&dv.plonk.gamma.0)?,
        zeta: ach_to_field::<StepField>(&dv.plonk.zeta)?,
    };

    // raw_bulletproof_challenges: 16 prechallenges (LE-limb 128 bit each).
    let mut raw_bp_vec: Vec<StepField> = Vec::with_capacity(STEP_IPA_ROUNDS);
    for a in dv.bulletproof_challenges.0.iter() {
        raw_bp_vec.push(ach_to_field::<StepField>(&a.prechallenge)?);
    }
    let raw_bulletproof_challenges: [StepField; STEP_IPA_ROUNDS] = raw_bp_vec
        .try_into()
        .map_err(|_| ConvertError::Field("expected 16 bp challenges".to_string()))?;

    // branch_data
    let step_domain_log2_u8: u8 = dv.branch_data.domain_log2.0 .0 as u8;
    let proofs_verified_mask = match dv.branch_data.proofs_verified {
        mina_p2p_messages::v2::PicklesBaseProofsVerifiedStableV1::N0 => [false, false],
        mina_p2p_messages::v2::PicklesBaseProofsVerifiedStableV1::N1 => [false, true],
        mina_p2p_messages::v2::PicklesBaseProofsVerifiedStableV1::N2 => [true, true],
    };
    let branch_data = BranchData {
        domain_log2: StepField::from(step_domain_log2_u8 as u64),
        proofs_verified_mask,
    };

    // sponge_digest_before_evaluations: 4 LE limbs (256 bits → Fp).
    let sponge_digest_before_evaluations =
        limbs_to_field::<StepField>(&st.proof_state.sponge_digest_before_evaluations.0 .0)?;

    // challenge_polynomial_commitment (Vesta — Fq coords).
    let challenge_polynomial_commitment = point_to_vesta(&msg_wrap.challenge_polynomial_commitment)?;

    // prev_evals
    let prev_evals = to_chunked_all_evals(&p.prev_evals)?;
    let p_eval0_chunks = prev_evals.public_evals.zeta.clone();

    // prev step (Pallas) sgs + old bp challenges
    let mut prev_step_sgs: Vec<Pallas> = Vec::new();
    for p in &msg_step.challenge_polynomial_commitments {
        prev_step_sgs.push(point_to_pallas(p)?);
    }
    let mut prev_step_chals_raw: Vec<[StepField; STEP_IPA_ROUNDS]> = Vec::new();
    for chals in &msg_step.old_bulletproof_challenges {
        let mut row: Vec<StepField> = Vec::with_capacity(STEP_IPA_ROUNDS);
        for a in chals.0.iter() {
            row.push(ach_to_field::<StepField>(&a.prechallenge)?);
        }
        let arr: [StepField; STEP_IPA_ROUNDS] = row
            .try_into()
            .map_err(|_| ConvertError::Field("prev step bp challenges length".to_string()))?;
        prev_step_chals_raw.push(arr);
    }

    // prev wrap old bp challenges. PaddedSeq is fixed-length 2, but each row
    // is a WrapChallengesVector (PaddedSeq<A, 15>). The semantic length =
    // proofs-verified (`mpv`), so we only keep the trailing `mpv` rows
    // (front-padding with dummies is reapplied by `into_verifiable`).
    let mpv = prev_step_sgs.len();
    let mut prev_wrap_chals_raw: Vec<[WrapField; WRAP_IPA_ROUNDS]> = Vec::with_capacity(mpv);
    let wrap_rows = &msg_wrap.old_bulletproof_challenges.0;
    // PaddedSeq is len-2; take the last `mpv` rows.
    for chals in wrap_rows.iter().skip(2 - mpv) {
        let mut row: Vec<WrapField> = Vec::with_capacity(WRAP_IPA_ROUNDS);
        for a in chals.0 .0.iter() {
            row.push(ach_to_field::<WrapField>(&a.prechallenge)?);
        }
        let arr: [WrapField; WRAP_IPA_ROUNDS] = row
            .try_into()
            .map_err(|_| ConvertError::Field("prev wrap bp challenges length".to_string()))?;
        prev_wrap_chals_raw.push(arr);
    }

    Ok(OcamlProof {
        raw_plonk,
        raw_bulletproof_challenges,
        branch_data,
        sponge_digest_before_evaluations,
        challenge_polynomial_commitment,
        step_domain_log2: step_domain_log2_u8,
        prev_evals,
        p_eval0_chunks,
        prev_step_sgs,
        prev_step_chals_raw,
        prev_wrap_chals_raw,
    })
}

// ---------------------------------------------------------------------------
// ChunkedAllEvals construction
// ---------------------------------------------------------------------------

fn bigints_to_field_vec(
    bs: &[mina_p2p_messages::bigint::BigInt],
) -> Result<Vec<StepField>, ConvertError> {
    bs.iter().map(bigint_to_field::<StepField>).collect()
}

fn array_pair_to_chunked(
    pair: &(
        mina_p2p_messages::array::ArrayN16<mina_p2p_messages::bigint::BigInt>,
        mina_p2p_messages::array::ArrayN16<mina_p2p_messages::bigint::BigInt>,
    ),
) -> Result<PointEvaluations<Vec<StepField>>, ConvertError> {
    Ok(PointEvaluations {
        zeta: bigints_to_field_vec(pair.0.as_ref())?,
        zeta_omega: bigints_to_field_vec(pair.1.as_ref())?,
    })
}

fn to_chunked_all_evals(
    p: &mina_p2p_messages::v2::PicklesProofProofsVerified2ReprStableV2PrevEvals,
) -> Result<ChunkedAllEvals, ConvertError> {
    let ft_eval1 = bigint_to_field::<StepField>(&p.ft_eval1)?;
    let evals_outer = &p.evals;
    // public_input is `(BigInt, BigInt)` — single chunk each side.
    let public_evals = PointEvaluations {
        zeta: alloc::vec![bigint_to_field::<StepField>(&evals_outer.public_input.0)?],
        zeta_omega: alloc::vec![bigint_to_field::<StepField>(&evals_outer.public_input.1)?],
    };
    let e: &PicklesProofProofsVerified2ReprStableV2PrevEvalsEvalsEvals = &evals_outer.evals;

    let mut w = Vec::with_capacity(15);
    for pair in e.w.0.iter() {
        w.push(array_pair_to_chunked(pair)?);
    }
    let w: [_; 15] = w
        .try_into()
        .map_err(|_| ConvertError::Field("w length".to_string()))?;

    let mut coefficients = Vec::with_capacity(15);
    for pair in e.coefficients.0.iter() {
        coefficients.push(array_pair_to_chunked(pair)?);
    }
    let coefficients: [_; 15] = coefficients
        .try_into()
        .map_err(|_| ConvertError::Field("coefficients length".to_string()))?;

    let z = array_pair_to_chunked(&e.z)?;

    let mut s = Vec::with_capacity(6);
    for pair in e.s.0.iter() {
        s.push(array_pair_to_chunked(pair)?);
    }
    let s: [_; 6] = s
        .try_into()
        .map_err(|_| ConvertError::Field("s length".to_string()))?;

    let index = [
        array_pair_to_chunked(&e.generic_selector)?,
        array_pair_to_chunked(&e.poseidon_selector)?,
        array_pair_to_chunked(&e.complete_add_selector)?,
        array_pair_to_chunked(&e.mul_selector)?,
        array_pair_to_chunked(&e.emul_selector)?,
        array_pair_to_chunked(&e.endomul_scalar_selector)?,
    ];

    Ok(ChunkedAllEvals {
        ft_eval1,
        public_evals,
        z,
        w,
        coefficients,
        s,
        index,
    })
}

// ---------------------------------------------------------------------------
// Wrap kimchi ProverProof reconstruction (stub for M3 — to be filled in)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Wrap kimchi ProverProof reconstruction
// ---------------------------------------------------------------------------

/// `(BigInt, BigInt)` (x, y) → single-chunk `PolyComm<Pallas>`. Used for every
/// commitment in `PicklesWrapWireProofStableV1` (w_comm, z_comm, t_comm).
fn point_pair_to_polycomm(
    p: &(mina_p2p_messages::bigint::BigInt, mina_p2p_messages::bigint::BigInt),
) -> Result<PolyComm<Pallas>, ConvertError> {
    Ok(PolyComm {
        chunks: alloc::vec![point_to_pallas(p)?],
    })
}

/// `(BigInt, BigInt)` → single-chunk `PointEvaluations<Vec<F>>`. The kimchi
/// `evals` shape is chunked (Vec); a wrap proof has `nc = 1`, so one chunk.
fn pair_to_point_eval(
    p: &(mina_p2p_messages::bigint::BigInt, mina_p2p_messages::bigint::BigInt),
) -> Result<PointEvaluations<alloc::vec::Vec<WrapField>>, ConvertError> {
    Ok(PointEvaluations {
        zeta: alloc::vec![bigint_to_field::<WrapField>(&p.0)?],
        zeta_omega: alloc::vec![bigint_to_field::<WrapField>(&p.1)?],
    })
}

/// `Pickles.Dummy.Ipa.Wrap.sg` — the protocol-fixed dummy Pallas point used to
/// front-pad the prev-step CPC list to `PADDED_LENGTH = 2`. Derived
/// deterministically by OCaml as `Pickles.Ipa.Wrap.compute_sg(challenges)`
/// where `challenges` are 15 raw `Ro.scalar_chal()` values (the same draw that
/// produces `dummy_ipa_wrap_expanded` in `convert.rs`). Because Mina's wrap
/// SRS is universal across mainnet, devnet, and o1js v2.15, this point is also
/// universal — we extracted the 33-byte kimchi-compressed encoding from
/// `fixtures/nrr/proof.serde.json::prev_challenges[0].comm.chunks[0]` (nrr is
/// `mpv = 0`, so both `prev_challenges` entries are this dummy) and decode
/// it lazily. Both `nrr` entries and `simplechain/wrap0`'s leading entry
/// match this constant byte-for-byte (verified by `dummy_wrap_sg_matches_nrr`
/// and `dummy_wrap_sg_matches_simplechain`).
const DUMMY_WRAP_SG_COMPRESSED_HEX: &str =
    "48b536e84654a55f4ffdfffdf591bd9d3ca1704bcef05ca59dc26448dedfd31100";

pub(super) fn dummy_wrap_sg() -> Pallas {
    use ark_serialize::CanonicalDeserialize;
    use std::sync::OnceLock;
    static CELL: OnceLock<Pallas> = OnceLock::new();
    *CELL.get_or_init(|| {
        let bytes = hex::decode(DUMMY_WRAP_SG_COMPRESSED_HEX)
            .expect("DUMMY_WRAP_SG_COMPRESSED_HEX is valid hex");
        Pallas::deserialize_compressed(&bytes[..])
            .expect("DUMMY_WRAP_SG_COMPRESSED_HEX decodes to a Pallas affine")
    })
}

/// Reconstruct the wrap kimchi `ProverProof<Pallas>` from the bin_prot wire
/// form. Direct field-by-field projection (no JSON round-trip): kimchi types
/// are public and the wire layout is a 1:1 map after `BigInt → Fp/Fq` /
/// `(BigInt, BigInt) → Pallas`.
pub fn to_wrap_proof(
    p: &PicklesProofProofsVerified2ReprStableV2,
) -> Result<WrapProof, ConvertError> {
    let wp: &PicklesWrapWireProofStableV1 = &p.proof;

    // ----- ProverCommitments
    let mut w_comm = alloc::vec::Vec::with_capacity(15);
    for pair in wp.commitments.w_comm.0.iter() {
        w_comm.push(point_pair_to_polycomm(pair)?);
    }
    let w_comm: [PolyComm<Pallas>; 15] = w_comm
        .try_into()
        .map_err(|_| ConvertError::Field("w_comm length".to_string()))?;

    let z_comm = point_pair_to_polycomm(&wp.commitments.z_comm)?;

    // t_comm is a PaddedSeq of 7 commitments combined into ONE PolyComm with
    // 7 chunks (kimchi's quotient polynomial is high-degree → multiple chunks).
    let mut t_chunks = alloc::vec::Vec::with_capacity(7);
    for pair in wp.commitments.t_comm.0.iter() {
        t_chunks.push(point_to_pallas(pair)?);
    }
    let t_comm = PolyComm { chunks: t_chunks };

    let commitments = ProverCommitments {
        w_comm,
        z_comm,
        t_comm,
        lookup: None,
    };

    // ----- OpeningProof (IPA)
    let mut lr: alloc::vec::Vec<(Pallas, Pallas)> = alloc::vec::Vec::with_capacity(15);
    for pair in wp.bulletproof.lr.as_ref() {
        lr.push((point_to_pallas(&pair.0)?, point_to_pallas(&pair.1)?));
    }
    let delta = point_to_pallas(&wp.bulletproof.delta)?;
    let z1 = bigint_to_field::<WrapField>(&wp.bulletproof.z_1)?;
    let z2 = bigint_to_field::<WrapField>(&wp.bulletproof.z_2)?;
    let sg = point_to_pallas(&wp.bulletproof.challenge_polynomial_commitment)?;

    let opening = OpeningProof { lr, delta, z1, z2, sg };

    // ----- ProofEvaluations
    let ev = &wp.evaluations;
    let mut w_evals = alloc::vec::Vec::with_capacity(15);
    for pair in ev.w.0.iter() {
        w_evals.push(pair_to_point_eval(pair)?);
    }
    let w_evals: [_; 15] = w_evals
        .try_into()
        .map_err(|_| ConvertError::Field("w evals length".to_string()))?;

    let mut coeff_evals = alloc::vec::Vec::with_capacity(15);
    for pair in ev.coefficients.0.iter() {
        coeff_evals.push(pair_to_point_eval(pair)?);
    }
    let coeff_evals: [_; 15] = coeff_evals
        .try_into()
        .map_err(|_| ConvertError::Field("coefficient evals length".to_string()))?;

    let z_eval = pair_to_point_eval(&ev.z)?;

    let mut s_evals = alloc::vec::Vec::with_capacity(6);
    for pair in ev.s.0.iter() {
        s_evals.push(pair_to_point_eval(pair)?);
    }
    let s_evals: [_; 6] = s_evals
        .try_into()
        .map_err(|_| ConvertError::Field("s evals length".to_string()))?;

    let evals = ProofEvaluations {
        public: None,
        w: w_evals,
        z: z_eval,
        s: s_evals,
        coefficients: coeff_evals,
        generic_selector: pair_to_point_eval(&ev.generic_selector)?,
        poseidon_selector: pair_to_point_eval(&ev.poseidon_selector)?,
        complete_add_selector: pair_to_point_eval(&ev.complete_add_selector)?,
        mul_selector: pair_to_point_eval(&ev.mul_selector)?,
        emul_selector: pair_to_point_eval(&ev.emul_selector)?,
        endomul_scalar_selector: pair_to_point_eval(&ev.endomul_scalar_selector)?,
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
    };

    let ft_eval1 = bigint_to_field::<WrapField>(&wp.ft_eval1)?;

    // ----- prev_challenges
    //
    // OCaml `fetch_blockchain_fixture.ml`'s `chal_polys` is exactly this:
    // pad the step CPC list front to length 2 with `Dummy.Ipa.Wrap.sg`, zip
    // with the (already len-2) prev wrap old bp challenges, and endo-expand
    // each row's prechallenges. The resulting Vec<RecursionChallenge> is the
    // wrap proof's `prev_challenges`.
    let st = &p.statement;
    let prev_step_sgs = &st.messages_for_next_step_proof.challenge_polynomial_commitments;
    let prev_wrap_rows = &st
        .proof_state
        .messages_for_next_wrap_proof
        .old_bulletproof_challenges
        .0;
    let mpv = prev_step_sgs.len();

    // Front-pad sg list to length 2 with dummy.
    let mut padded_sgs: alloc::vec::Vec<Pallas> = alloc::vec::Vec::with_capacity(2);
    for _ in 0..(2_usize.saturating_sub(mpv)) {
        padded_sgs.push(dummy_wrap_sg());
    }
    for p in prev_step_sgs.iter() {
        padded_sgs.push(point_to_pallas(p)?);
    }

    let wrap_endo = endos::<Pallas>().1;
    let mut prev_challenges: alloc::vec::Vec<RecursionChallenge<Pallas>> =
        alloc::vec::Vec::with_capacity(2);
    for (sg, chals) in padded_sgs.iter().copied().zip(prev_wrap_rows.iter()) {
        // chals: PicklesReducedMessagesForNextProofOverSameFieldWrapChallengesVectorStableV2
        // = PaddedSeq<A, 15>. Endo-expand each prechallenge into Fq.
        let mut chal_vec: alloc::vec::Vec<WrapField> = alloc::vec::Vec::with_capacity(15);
        for a in chals.0 .0.iter() {
            let raw = ach_to_field::<WrapField>(&a.prechallenge)?;
            chal_vec.push(ScalarChallenge::new(raw).to_field(&wrap_endo));
        }
        prev_challenges.push(RecursionChallenge {
            chals: chal_vec,
            comm: PolyComm { chunks: alloc::vec![sg] },
        });
    }

    Ok(ProverProof {
        commitments,
        proof: opening,
        evals,
        ft_eval1,
        prev_challenges,
    })
}
