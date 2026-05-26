//! SP1 guest: out-of-circuit Pickles verification.
//!
//! At build time, `build.rs` reads the wrap `vk.serde.json` (path via the
//! `VK_JSON` env var) and writes a serialized [`pickles_verifier::Verifier`]
//! blob to `OUT_DIR/verifier.bin`. The guest `include_bytes!`s it and
//! reinstantiates the verifier mostly zero-parse via
//! [`pickles_verifier::serialize::decode_verifier_blob`] (pod-cast SRSes +
//! postcard wrap VK).
//!
//! At runtime, the host driver writes one
//! [`pickles_verifier::types::VerifiableProof`] to the guest stdin; the guest
//! reads it, runs [`pickles_verifier::verify`], and commits the boolean
//! result.

#![no_main]
sp1_zkvm::entrypoint!(main);

use pickles_verifier::serialize::decode_verifier_blob;
use pickles_verifier::types::VerifiableProof;
use pickles_verifier::verify;

/// 8-byte aligned wrapper around `include_bytes!`. The blob's pod-cast
/// sections (`PodVesta` / `PodPallas`) require 8-byte alignment for the
/// `bytemuck::cast_slice` casts inside `decode_verifier_blob`; raw
/// `include_bytes!` data is 1-byte aligned.
#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

static VERIFIER_BYTES: &Aligned<[u8]> =
    &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/verifier.bin")));

fn tracker(line: &[u8]) {
    sp1_zkvm::io::write(1, line);
}

pub fn main() {
    tracker(b"cycle-tracker-report-start:setup\n");
    let verifier = decode_verifier_blob(&VERIFIER_BYTES.0);
    let proof: VerifiableProof = sp1_zkvm::io::read();
    tracker(b"cycle-tracker-report-end:setup\n");

    tracker(b"cycle-tracker-report-start:verify\n");
    let valid = verify(&verifier, &proof);
    tracker(b"cycle-tracker-report-end:verify\n");

    sp1_zkvm::io::commit(&valid);
}
