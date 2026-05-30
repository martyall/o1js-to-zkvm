//! Decode the bin_prot wire form of a Mina blockchain SNARK (a.k.a. wrap
//! pickles proof) into the crate's canonical [`VerifiableProof`].
//!
//! The bytes this module consumes are what the Mina daemon's GraphQL serves
//! at `bestChain[0].protocolStateProof.base64` (after URL-safe base64 decode),
//! and what o1js's `Proof.toJSON()` embeds inside its `proof` string. Both
//! upstreams produce the same OCaml `Pickles.Proof.t` bin_prot encoding;
//! `mina_p2p_messages::v2::MinaBaseProofStableV2` is the Rust mirror.
//!
//! The conversion from this in-memory mirror to a `VerifiableProof` will be
//! built up iteratively: this initial module exposes a `decode_bytes` helper
//! that confirms the wire bytes are parseable; the field-by-field projection
//! into `VerifiableProof` lives in [`to_verifiable_proof`] and is filled out
//! in a later milestone.

use binprot::BinProtRead;
use mina_p2p_messages::v2::MinaBaseProofStableV2;

/// Decode raw bin_prot bytes (typically from a Mina daemon's
/// `protocolStateProof.base64` after URL-safe base64 decoding, or from the
/// `proof` field of o1js's `Proof.toJSON()` after base64 decode) into the
/// `mina_p2p_messages` mirror type.
///
/// This is a smoke test of bin_prot compatibility — if it succeeds, the
/// upstream daemon's stable version matches what `mina_p2p_messages` expects.
/// If it fails, the failure mode (truncated read, version tag mismatch, etc.)
/// is what we'd report for the SUMMARY writeup.
pub fn decode_bytes(bytes: &[u8]) -> Result<MinaBaseProofStableV2, binprot::Error> {
    MinaBaseProofStableV2::binprot_read(&mut &*bytes)
}
