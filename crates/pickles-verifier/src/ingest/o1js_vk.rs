//! Decode an o1js ZkProgram VK JSON (`{ data: base64, hash: decimal }`) and
//! produce a wrap [`WrapVerifierIndex`] that the verifier can consume.
//!
//! The `data` field is base64 of bin_prot of `MinaBaseVerificationKeyWireStableV1`
//! which carries only the per-circuit commitments (`wrap_index` — sigma,
//! coefficients, generic, psm, complete_add, mul, emul, endomul_scalar). The
//! math params (domain, max_poly_size, shifts, lookup_index=None, SRS hookup)
//! are universal across Mina's wrap circuit, so we read those from a template
//! VK (any `vk.serde.json` from the existing fixtures works — they share the
//! wrap params byte-for-byte) and only overwrite the commitments.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;

use base64::Engine as _;
use binprot::BinProtRead;
use mina_curves::pasta::Pallas;
use mina_p2p_messages::v2::MinaBaseVerificationKeyWireStableV1;
use o1_utils::FieldHelpers;
use poly_commitment::commitment::PolyComm;
use serde::Deserialize;

use crate::types::{StepField, WrapVerifierIndex};
use crate::wire::parse_wrap_vk;

#[derive(Debug, Deserialize)]
pub struct O1jsVkJson {
    pub data: String,
    /// `hash` is decimal Fp — informational, not used for verification.
    #[serde(default)]
    pub hash: Option<String>,
}

#[derive(Debug)]
pub enum VkError {
    Json(serde_json::Error),
    Base64(base64::DecodeError),
    BinProt(String),
    Field(String),
    Template(serde_json::Error),
}

impl core::fmt::Display for VkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VkError::Json(e) => write!(f, "o1js VK JSON: {e}"),
            VkError::Base64(e) => write!(f, "o1js VK base64: {e}"),
            VkError::BinProt(e) => write!(f, "o1js VK bin_prot: {e}"),
            VkError::Field(e) => write!(f, "o1js VK field: {e}"),
            VkError::Template(e) => write!(f, "template VK parse: {e}"),
        }
    }
}

impl std::error::Error for VkError {}

fn point(p: &(mina_p2p_messages::bigint::BigInt, mina_p2p_messages::bigint::BigInt)) -> Result<Pallas, VkError> {
    let x: StepField = StepField::from_bytes(p.0.as_ref())
        .map_err(|e| VkError::Field(format!("x: {e:?}")))?;
    let y: StepField = StepField::from_bytes(p.1.as_ref())
        .map_err(|e| VkError::Field(format!("y: {e:?}")))?;
    Ok(Pallas::new_unchecked(x, y))
}

fn poly1(p: &(mina_p2p_messages::bigint::BigInt, mina_p2p_messages::bigint::BigInt)) -> Result<PolyComm<Pallas>, VkError> {
    Ok(PolyComm { chunks: vec![point(p)?] })
}

/// Build a wrap VK from an o1js `verificationKey.json` and a template VK JSON.
/// The template supplies math params (domain, shifts, max_poly_size, ...) that
/// are universal across Mina's wrap circuit; only the per-circuit commitments
/// are overwritten from the o1js VK data.
pub fn parse_o1js_vk(json: &str, template_vk_json: &str) -> Result<WrapVerifierIndex, VkError> {
    let env: O1jsVkJson = serde_json::from_str(json).map_err(VkError::Json)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(env.data.as_str())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(env.data.as_str()))
        .map_err(VkError::Base64)?;
    let wire = MinaBaseVerificationKeyWireStableV1::binprot_read(&mut &bytes[..])
        .map_err(|e| VkError::BinProt(e.to_string()))?;
    let wi = &wire.wrap_index;

    let mut vk: WrapVerifierIndex =
        parse_wrap_vk(template_vk_json).map_err(VkError::Template)?;

    // sigma_comm: PaddedSeq<_, 7> → [PolyComm; 7]
    let sigma_iter: alloc::vec::Vec<PolyComm<Pallas>> = wi
        .sigma_comm
        .iter()
        .map(poly1)
        .collect::<Result<_, _>>()?;
    let sigma_arr: [PolyComm<Pallas>; 7] = sigma_iter
        .try_into()
        .map_err(|_| VkError::Field("sigma_comm length".to_string()))?;
    vk.sigma_comm = sigma_arr;

    let coeff_iter: alloc::vec::Vec<PolyComm<Pallas>> = wi
        .coefficients_comm
        .iter()
        .map(poly1)
        .collect::<Result<_, _>>()?;
    let coeff_arr: [PolyComm<Pallas>; 15] = coeff_iter
        .try_into()
        .map_err(|_| VkError::Field("coefficients_comm length".to_string()))?;
    vk.coefficients_comm = coeff_arr;

    vk.generic_comm = poly1(&wi.generic_comm)?;
    vk.psm_comm = poly1(&wi.psm_comm)?;
    vk.complete_add_comm = poly1(&wi.complete_add_comm)?;
    vk.mul_comm = poly1(&wi.mul_comm)?;
    vk.emul_comm = poly1(&wi.emul_comm)?;
    vk.endomul_scalar_comm = poly1(&wi.endomul_scalar_comm)?;

    Ok(vk)
}
