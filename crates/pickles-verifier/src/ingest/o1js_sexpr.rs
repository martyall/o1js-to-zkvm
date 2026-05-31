//! Build [`OcamlProof`] + [`WrapProof`] from an OCaml `sexp_of_t` tree of
//! `Pickles.Proof.Proofs_verified_2.Repr.Stable.V2`.
//!
//! Mirrors `wire::OcamlProof::parse` (yojson skeleton path) and
//! `bin_prot::to_wrap_proof` (openmina bin_prot path) field-for-field. Only the
//! syntax of the leaf decoders differs.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ark_ff::PrimeField;
use kimchi::proof::{
    PointEvaluations, ProofEvaluations, ProverCommitments, ProverProof, RecursionChallenge,
};
use mina_curves::pasta::{Pallas, Vesta};
use mina_poseidon::sponge::ScalarChallenge;
use o1_utils::FieldHelpers;
use poly_commitment::commitment::PolyComm;
use poly_commitment::ipa::{endos, OpeningProof};

use super::sexpr::Sexp;
use crate::types::{
    BranchData, ChunkedAllEvals, PlonkMinimal, StepField, WrapField, WrapProof,
    STEP_IPA_ROUNDS,
};
use crate::wire::{parse_field_be_hex, OcamlProof};

// ---------------------------------------------------------------------------
// Leaf decoders
// ---------------------------------------------------------------------------

fn combine_limbs_le<F: PrimeField>(atoms: &[Sexp]) -> Result<F, String> {
    let mut le = Vec::with_capacity(atoms.len() * 8);
    for a in atoms {
        let s = a.as_atom()?;
        let v = u64::from_str_radix(s, 16)
            .map_err(|e| format!("limb hex parse `{s}`: {e}"))?;
        le.extend_from_slice(&v.to_le_bytes());
    }
    le.resize(F::size_in_bytes(), 0);
    F::from_bytes(&le).map_err(|e| format!("field from LE bytes: {e:?}"))
}

/// `(l1 l2)` raw challenge OR `((inner (l1 l2)))` scalar challenge.
fn challenge<F: PrimeField>(s: &Sexp) -> Result<F, String> {
    let items = s.as_list()?;
    // Sniff: if the first element is a list with an `inner` field, drill into it.
    if !items.is_empty() {
        if let Sexp::List(pair) = &items[0] {
            if pair.len() == 2 {
                if let Ok(k) = pair[0].as_atom() {
                    if k == "inner" {
                        return combine_limbs_le::<F>(pair[1].as_list()?);
                    }
                }
            }
        }
    }
    // Fall through: treat the items themselves as the raw limbs.
    combine_limbs_le::<F>(items)
}

fn be_hex_atom<F: PrimeField>(s: &Sexp) -> Result<F, String> {
    let atom = s.as_atom()?;
    parse_field_be_hex(atom)
}

/// `(x_hex y_hex)` → affine point. Caller picks the curve via `mk`.
fn affine<C, F: PrimeField>(s: &Sexp, mk: impl Fn(F, F) -> C) -> Result<C, String> {
    let items = s.as_list()?;
    if items.len() != 2 {
        return Err(format!("affine: expected (x y), got {} items", items.len()));
    }
    Ok(mk(be_hex_atom(&items[0])?, be_hex_atom(&items[1])?))
}

/// OCaml `Hex64` byte rendered as a 1-char string (e.g. `"\t"` → 9).
fn ocaml_byte_atom(s: &Sexp) -> Result<u8, String> {
    let s = s.as_atom()?;
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err("ocaml byte: empty string".to_string());
    }
    Ok(bytes[0])
}

fn proofs_verified_mask(s: &Sexp) -> Result<[bool; 2], String> {
    // The sexp form for nullary variants is the bare atom (e.g. `N0`).
    let tag = match s {
        Sexp::Atom(a) => a.as_str(),
        Sexp::List(items) => {
            if items.is_empty() {
                return Err("proofs_verified: empty list".to_string());
            }
            items[0].as_atom()?
        }
    };
    match tag {
        "N0" => Ok([false, false]),
        "N1" => Ok([false, true]),
        "N2" => Ok([true, true]),
        other => Err(format!("proofs_verified: expected N0|N1|N2, got {other}")),
    }
}

fn bulletproof_vec<F: PrimeField, const N: usize>(s: &Sexp) -> Result<[F; N], String> {
    let items = s.as_list()?;
    if items.len() != N {
        return Err(format!("bulletproof: expected {N} entries, got {}", items.len()));
    }
    let mut out = Vec::with_capacity(N);
    for it in items {
        let prechal = it.field("prechallenge")?;
        out.push(challenge::<F>(prechal)?);
    }
    out.try_into()
        .map_err(|_| "bulletproof: length invariant".to_string())
}

// ---------------------------------------------------------------------------
// Eval shape parsers
// ---------------------------------------------------------------------------

/// `(zeta_hex omega_hex)` → 1-chunk PointEvaluations.
fn point_eval_flat(s: &Sexp) -> Result<PointEvaluations<Vec<StepField>>, String> {
    let items = s.as_list()?;
    if items.len() != 2 {
        return Err("public_input eval: expected (zeta omega)".to_string());
    }
    Ok(PointEvaluations {
        zeta: alloc::vec![be_hex_atom(&items[0])?],
        zeta_omega: alloc::vec![be_hex_atom(&items[1])?],
    })
}

/// `((zeta_chunks…) (omega_chunks…))` → chunked PointEvaluations.
fn point_eval_chunked(s: &Sexp) -> Result<PointEvaluations<Vec<StepField>>, String> {
    let items = s.as_list()?;
    if items.len() != 2 {
        return Err("chunked eval: expected (zeta_chunks omega_chunks)".to_string());
    }
    let parse_chunks = |sx: &Sexp| -> Result<Vec<StepField>, String> {
        sx.as_list()?.iter().map(be_hex_atom).collect()
    };
    let zeta = parse_chunks(&items[0])?;
    let zeta_omega = parse_chunks(&items[1])?;
    if zeta.len() != zeta_omega.len() {
        return Err("chunked eval: zeta/omega chunk count mismatch".to_string());
    }
    Ok(PointEvaluations { zeta, zeta_omega })
}

fn fixed_chunked<const N: usize>(
    s: &Sexp,
) -> Result<[PointEvaluations<Vec<StepField>>; N], String> {
    let items = s.as_list()?;
    if items.len() != N {
        return Err(format!("evals: expected {N} columns, got {}", items.len()));
    }
    let out: Vec<_> = items.iter().map(point_eval_chunked).collect::<Result<_, _>>()?;
    out.try_into()
        .map_err(|_| "evals: length invariant".to_string())
}

fn parse_all_evals(prev_evals: &Sexp) -> Result<ChunkedAllEvals, String> {
    let ft_eval1 = be_hex_atom(prev_evals.field("ft_eval1")?)?;
    let evals_outer = prev_evals.field("evals")?;
    let public_evals = point_eval_flat(evals_outer.field("public_input")?)?;
    let inner = evals_outer.field("evals")?;

    let z = point_eval_chunked(inner.field("z")?)?;
    let w = fixed_chunked::<15>(inner.field("w")?)?;
    let coefficients = fixed_chunked::<15>(inner.field("coefficients")?)?;
    let s = fixed_chunked::<6>(inner.field("s")?)?;

    let index = [
        point_eval_chunked(inner.field("generic_selector")?)?,
        point_eval_chunked(inner.field("poseidon_selector")?)?,
        point_eval_chunked(inner.field("complete_add_selector")?)?,
        point_eval_chunked(inner.field("mul_selector")?)?,
        point_eval_chunked(inner.field("emul_selector")?)?,
        point_eval_chunked(inner.field("endomul_scalar_selector")?)?,
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
// OcamlProof from sexp
// ---------------------------------------------------------------------------

pub fn ocaml_proof_from_sexp(root: &Sexp) -> Result<OcamlProof, String> {
    let statement = root.field("statement")?;
    let proof_state = statement.field("proof_state")?;
    let deferred = proof_state.field("deferred_values")?;

    let plonk = deferred.field("plonk")?;
    let raw_plonk = PlonkMinimal {
        alpha: challenge::<StepField>(plonk.field("alpha")?)?,
        beta: challenge::<StepField>(plonk.field("beta")?)?,
        gamma: challenge::<StepField>(plonk.field("gamma")?)?,
        zeta: challenge::<StepField>(plonk.field("zeta")?)?,
    };

    let raw_bulletproof_challenges = bulletproof_vec::<StepField, STEP_IPA_ROUNDS>(
        deferred.field("bulletproof_challenges")?,
    )?;

    let branch_data_s = deferred.field("branch_data")?;
    let step_domain_log2 = ocaml_byte_atom(branch_data_s.field("domain_log2")?)?;
    let branch_data = BranchData {
        domain_log2: StepField::from(step_domain_log2 as u64),
        proofs_verified_mask: proofs_verified_mask(branch_data_s.field("proofs_verified")?)?,
    };

    let sponge_digest_before_evaluations = combine_limbs_le::<StepField>(
        proof_state.field("sponge_digest_before_evaluations")?.as_list()?,
    )?;

    let msg_wrap = proof_state.field("messages_for_next_wrap_proof")?;
    let challenge_polynomial_commitment = affine::<Vesta, WrapField>(
        msg_wrap.field("challenge_polynomial_commitment")?,
        Vesta::new_unchecked,
    )?;

    let msg_step = statement.field("messages_for_next_step_proof")?;
    let prev_step_sgs = msg_step
        .field("challenge_polynomial_commitments")?
        .as_list()?
        .iter()
        .map(|p| affine::<Pallas, StepField>(p, Pallas::new_unchecked))
        .collect::<Result<Vec<_>, String>>()?;
    let prev_step_chals_raw = msg_step
        .field("old_bulletproof_challenges")?
        .as_list()?
        .iter()
        .map(bulletproof_vec::<StepField, STEP_IPA_ROUNDS>)
        .collect::<Result<Vec<_>, String>>()?;
    let prev_wrap_chals_raw = msg_wrap
        .field("old_bulletproof_challenges")?
        .as_list()?
        .iter()
        .map(bulletproof_vec::<WrapField, { crate::types::WRAP_IPA_ROUNDS }>)
        .collect::<Result<Vec<_>, String>>()?;

    let prev_evals = parse_all_evals(root.field("prev_evals")?)?;
    let p_eval0_chunks = prev_evals.public_evals.zeta.clone();

    Ok(OcamlProof {
        raw_plonk,
        raw_bulletproof_challenges,
        branch_data,
        sponge_digest_before_evaluations,
        challenge_polynomial_commitment,
        step_domain_log2,
        prev_evals,
        p_eval0_chunks,
        prev_step_sgs,
        prev_step_chals_raw,
        prev_wrap_chals_raw,
    })
}

// ---------------------------------------------------------------------------
// WrapProof from sexp
// ---------------------------------------------------------------------------

fn point_pair_polycomm(s: &Sexp) -> Result<PolyComm<Pallas>, String> {
    Ok(PolyComm {
        chunks: alloc::vec![affine::<Pallas, StepField>(s, Pallas::new_unchecked)?],
    })
}

fn pair_to_point_eval_wrap(s: &Sexp) -> Result<PointEvaluations<Vec<WrapField>>, String> {
    let items = s.as_list()?;
    if items.len() != 2 {
        return Err("wrap eval pair: expected (zeta omega)".to_string());
    }
    Ok(PointEvaluations {
        zeta: alloc::vec![be_hex_atom::<WrapField>(&items[0])?],
        zeta_omega: alloc::vec![be_hex_atom::<WrapField>(&items[1])?],
    })
}

pub fn to_wrap_proof(root: &Sexp) -> Result<WrapProof, String> {
    let proof = root.field("proof")?;
    let commitments_s = proof.field("commitments")?;

    // w_comm: 15 points
    let w_comm_items = commitments_s.field("w_comm")?.as_list()?;
    if w_comm_items.len() != 15 {
        return Err(format!("w_comm: expected 15 points, got {}", w_comm_items.len()));
    }
    let mut w_comm = Vec::with_capacity(15);
    for pt in w_comm_items {
        w_comm.push(point_pair_polycomm(pt)?);
    }
    let w_comm: [PolyComm<Pallas>; 15] = w_comm
        .try_into()
        .map_err(|_| "w_comm length".to_string())?;

    // z_comm: single point
    let z_comm = point_pair_polycomm(commitments_s.field("z_comm")?)?;

    // t_comm: list of 7 points → one PolyComm with 7 chunks
    let t_items = commitments_s.field("t_comm")?.as_list()?;
    let mut t_chunks = Vec::with_capacity(t_items.len());
    for pt in t_items {
        t_chunks.push(affine::<Pallas, StepField>(pt, Pallas::new_unchecked)?);
    }
    let t_comm = PolyComm { chunks: t_chunks };

    let commitments = ProverCommitments {
        w_comm,
        z_comm,
        t_comm,
        lookup: None,
    };

    // ----- OpeningProof
    let bp = proof.field("bulletproof")?;
    let lr_items = bp.field("lr")?.as_list()?;
    let mut lr: Vec<(Pallas, Pallas)> = Vec::with_capacity(lr_items.len());
    for pair in lr_items {
        let pair_items = pair.as_list()?;
        if pair_items.len() != 2 {
            return Err(format!("lr pair: expected 2, got {}", pair_items.len()));
        }
        let l = affine::<Pallas, StepField>(&pair_items[0], Pallas::new_unchecked)?;
        let r = affine::<Pallas, StepField>(&pair_items[1], Pallas::new_unchecked)?;
        lr.push((l, r));
    }
    let delta = affine::<Pallas, StepField>(bp.field("delta")?, Pallas::new_unchecked)?;
    let z1 = be_hex_atom::<WrapField>(bp.field("z_1")?)?;
    let z2 = be_hex_atom::<WrapField>(bp.field("z_2")?)?;
    let sg = affine::<Pallas, StepField>(
        bp.field("challenge_polynomial_commitment")?,
        Pallas::new_unchecked,
    )?;
    let opening = OpeningProof { lr, delta, z1, z2, sg };

    // ----- Evaluations
    let ev = proof.field("evaluations")?;
    let mut w_evals = Vec::with_capacity(15);
    for pair in ev.field("w")?.as_list()? {
        w_evals.push(pair_to_point_eval_wrap(pair)?);
    }
    let w_evals: [_; 15] = w_evals
        .try_into()
        .map_err(|_| "w evals length".to_string())?;

    let mut coeff_evals = Vec::with_capacity(15);
    for pair in ev.field("coefficients")?.as_list()? {
        coeff_evals.push(pair_to_point_eval_wrap(pair)?);
    }
    let coeff_evals: [_; 15] = coeff_evals
        .try_into()
        .map_err(|_| "coefficient evals length".to_string())?;

    let z_eval = pair_to_point_eval_wrap(ev.field("z")?)?;

    let mut s_evals = Vec::with_capacity(6);
    for pair in ev.field("s")?.as_list()? {
        s_evals.push(pair_to_point_eval_wrap(pair)?);
    }
    let s_evals: [_; 6] = s_evals
        .try_into()
        .map_err(|_| "s evals length".to_string())?;

    let evals = ProofEvaluations {
        public: None,
        w: w_evals,
        z: z_eval,
        s: s_evals,
        coefficients: coeff_evals,
        generic_selector: pair_to_point_eval_wrap(ev.field("generic_selector")?)?,
        poseidon_selector: pair_to_point_eval_wrap(ev.field("poseidon_selector")?)?,
        complete_add_selector: pair_to_point_eval_wrap(ev.field("complete_add_selector")?)?,
        mul_selector: pair_to_point_eval_wrap(ev.field("mul_selector")?)?,
        emul_selector: pair_to_point_eval_wrap(ev.field("emul_selector")?)?,
        endomul_scalar_selector: pair_to_point_eval_wrap(ev.field("endomul_scalar_selector")?)?,
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

    let ft_eval1 = be_hex_atom::<WrapField>(proof.field("ft_eval1")?)?;

    // ----- prev_challenges (front-padded with dummy_wrap_sg, zipped with
    // prev-wrap old_bulletproof_challenges, endo-expanded).
    let statement = root.field("statement")?;
    let prev_step_sgs_s = statement
        .field("messages_for_next_step_proof")?
        .field("challenge_polynomial_commitments")?
        .as_list()?;
    let prev_wrap_rows_s = statement
        .field("proof_state")?
        .field("messages_for_next_wrap_proof")?
        .field("old_bulletproof_challenges")?
        .as_list()?;
    let mpv = prev_step_sgs_s.len();

    let mut padded_sgs: Vec<Pallas> = Vec::with_capacity(2);
    for _ in 0..(2_usize.saturating_sub(mpv)) {
        padded_sgs.push(super::bin_prot::dummy_wrap_sg());
    }
    for p in prev_step_sgs_s {
        padded_sgs.push(affine::<Pallas, StepField>(p, Pallas::new_unchecked)?);
    }

    // OCaml `sexp_of_t` strips the leading dummy entries from
    // `messages_for_next_wrap_proof.old_bulletproof_challenges` (so the sexp
    // list has only `mpv` entries — empty for ZkProgram), but bin_prot keeps
    // them as a fixed-length-2 PaddedSeq. We reconstruct the dummy entries
    // here using the same derivation (`dummy_ipa_wrap_expanded`) used by
    // `OcamlProof::into_verifiable`. Result has exactly 2 entries.
    let wrap_endo = endos::<Pallas>().1;
    let dummy_chals: Vec<WrapField> =
        crate::convert::dummy_ipa_wrap_expanded(&wrap_endo).to_vec();

    let mut chal_rows: Vec<Vec<WrapField>> = Vec::with_capacity(2);
    let prev_wrap_mpv = prev_wrap_rows_s.len();
    for _ in 0..(2_usize.saturating_sub(prev_wrap_mpv)) {
        chal_rows.push(dummy_chals.clone());
    }
    for chals_s in prev_wrap_rows_s.iter() {
        let chals_items = chals_s.as_list()?;
        let mut chal_vec: Vec<WrapField> = Vec::with_capacity(chals_items.len());
        for entry in chals_items {
            let prechal = entry.field("prechallenge")?;
            let raw = challenge::<WrapField>(prechal)?;
            chal_vec.push(ScalarChallenge::new(raw).to_field(&wrap_endo));
        }
        chal_rows.push(chal_vec);
    }

    let mut prev_challenges: Vec<RecursionChallenge<Pallas>> = Vec::with_capacity(2);
    for (sg, chals) in padded_sgs.iter().copied().zip(chal_rows.into_iter()) {
        prev_challenges.push(RecursionChallenge {
            chals,
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
