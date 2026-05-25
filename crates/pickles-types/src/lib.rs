//! Out-of-circuit Pickles verifier, translated from the PureScript
//! `Pickles.Verify` + `Test.Pickles.Sideload.Loader`.
//!
//! Layering mirrors the PureScript side:
//!
//!   * [`wire`] (std) — the serde-deserializable form of the four
//!     OCaml-serialized fixture files, plus parsing. Host-side only.
//!   * [`convert`] (std) — host-side conversion of the parsed wire data
//!     into the verifier types (`Verifier::new` + `OcamlProof::into_verifiable`);
//!     port of the PureScript `Test.Pickles.Sideload.Loader` + `mkVerifier`.
//!   * the verifier types (`Verifier`, `VerifiableProof`) + `verify`
//!     (added next) are `no_std` + `alloc` so they run in the SP1 guest.
//!
//! Primitives (Pasta fields/curves, Poseidon, the kimchi `VerifierIndex` /
//! `ProverProof` serde, SRS/MSM, `batch_verify`, the linearization
//! interpreter) come from the upstream proof-systems crates — only the
//! pickles-specific glue is translated here.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod types;

#[cfg(feature = "std")]
pub mod wire;

#[cfg(feature = "std")]
pub mod convert;
