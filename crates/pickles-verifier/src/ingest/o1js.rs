//! Parse an o1js `Proof.toJSON()` payload and route through [`super::bin_prot`].
//!
//! Shape (from o1js@v2.15 `src/lib/proof-system/proof.ts:61–69`):
//!
//! ```json
//! {
//!   "publicInput":  ["0x...", ...],
//!   "publicOutput": ["0x...", ...],
//!   "maxProofsVerified": 0 | 1 | 2,
//!   "proof": "<base64 of OCaml Pickles.Proof.t bin_prot>"
//! }
//! ```
//!
//! The `proof` string is the same OCaml bin_prot encoding the Mina daemon
//! serves for blockchain state proofs, so we just base64-decode and delegate.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::Engine as _;
use mina_p2p_messages::v2::MinaBaseProofStableV2;
use serde::Deserialize;

use crate::types::{StepField, VerifiableProof, WrapVerifierIndex};

/// Lightweight serde projection of the o1js JSON envelope; we only care about
/// the bin_prot blob and the public input/output field strings here. The
/// `maxProofsVerified` tag is informational — `MinaBaseProofStableV2` already
/// carries the proofs-verified prefix mask in its statement.
#[derive(Debug, Deserialize)]
pub struct O1jsProofJson {
    #[serde(default)]
    pub public_input: Vec<String>,
    #[serde(default)]
    pub public_output: Vec<String>,
    #[serde(default)]
    pub max_proofs_verified: u8,
    pub proof: String,
}

/// Parse the JSON envelope and base64-decode the inner proof field. The
/// returned `MinaBaseProofStableV2` is then convertible to a `VerifiableProof`
/// via the same path as a Nori-style daemon-fetched proof.
pub fn parse(json: &str) -> Result<(O1jsProofJson, MinaBaseProofStableV2), ParseError> {
    let envelope: O1jsProofJson = serde_json::from_str(json).map_err(ParseError::Json)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.proof)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&envelope.proof))
        .map_err(ParseError::Base64)?;
    let proof = super::bin_prot::decode_bytes(&bytes)
        .map_err(|e: binprot::Error| ParseError::BinProt(e.to_string()))?;
    Ok((envelope, proof))
}

#[derive(Debug)]
pub enum ParseError {
    Json(serde_json::Error),
    Base64(base64::DecodeError),
    BinProt(String),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Json(e) => write!(f, "o1js JSON parse: {e}"),
            ParseError::Base64(e) => write!(f, "o1js base64 decode: {e}"),
            ParseError::BinProt(e) => write!(f, "o1js inner bin_prot decode: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// Unified entry point: handles both wire formats (bin_prot from daemon /
// blockchain SNARK, sexpr from o1js ZkProgram).
// ---------------------------------------------------------------------------

/// Parse an o1js JSON proof and produce a [`VerifiableProof`], routing
/// automatically between the bin_prot path (daemon-shape proofs) and the
/// sexpr path (o1js `Pickles.proofToBase64` proofs). Format is sniffed from
/// the first non-whitespace byte of the base64-decoded `proof` field: `(` →
/// sexpr; otherwise → bin_prot.
pub fn parse_to_verifiable(
    json: &str,
    wrap_vk: &WrapVerifierIndex,
    app_state: &[StepField],
) -> Result<VerifiableProof, String> {
    let envelope: O1jsProofJson =
        serde_json::from_str(json).map_err(|e| format!("o1js JSON: {e}"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope.proof.as_str())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(envelope.proof.as_str()))
        .map_err(|e| format!("o1js base64: {e}"))?;

    // Sniff: skip leading ASCII whitespace, then look at the first byte.
    let first = bytes
        .iter()
        .copied()
        .find(|&b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'));

    if first == Some(b'(') {
        // sexpr path
        let text = core::str::from_utf8(&bytes)
            .map_err(|e| format!("o1js sexpr UTF-8: {e}"))?;
        let tree = super::sexpr::parse(text).map_err(|e| e.to_string())?;
        let ocaml = super::o1js_sexpr::ocaml_proof_from_sexp(&tree)?;
        let wrap = super::o1js_sexpr::to_wrap_proof(&tree)?;
        ocaml.into_verifiable(wrap, wrap_vk, app_state)
    } else {
        // bin_prot path
        let parsed = super::bin_prot::to_verifiable_proof(&bytes, wrap_vk, app_state)
            .map_err(|e| e.to_string())?;
        Ok(parsed)
    }
}
