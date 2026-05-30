//! Host-side ingestion adapters that turn external proof formats into the
//! crate's canonical [`VerifiableProof`].
//!
//! Layering (all gated behind the `ingest-bin-prot` feature, which also
//! implies `std`):
//!
//!   * [`bin_prot`] — decode `mina_p2p_messages::v2::MinaBaseProofStableV2`
//!     bytes (the bin_prot encoding the Mina daemon serves via
//!     `bestChain.protocolStateProof.base64` and o1js's `Proof.toJSON()`
//!     bundles inside its `proof` field) into a [`VerifiableProof`].
//!   * [`o1js`] — thin wrapper that parses o1js JSON, extracts the inner
//!     base64 of bin_prot, and delegates to [`bin_prot`].
//!
//! The existing `wire` + `convert` modules continue to serve the OCaml fixture
//! path used by the test suite and the SP1 host driver; nothing about the
//! `no_std` core changes.

pub mod bin_prot;
pub mod o1js;
