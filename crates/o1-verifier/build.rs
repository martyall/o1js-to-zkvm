//! Build script — bake a `pickles_verifier::Verifier` blob into the SP1
//! guest. Reads `VK_JSON` (the wrap `vk.serde.json` path), parses it via
//! `pickles_verifier::wire`, loads the precomputed Vesta + Pallas SRSes from
//! `poly_commitment::precomputed_srs`, encodes the lot via
//! `pickles_verifier::serialize::encode_verifier_blob`, and writes the blob
//! to `OUT_DIR/verifier.bin`. The guest `include_bytes!`s it and reinstantiates
//! the verifier mostly zero-parse (pod-cast SRSes + postcard wrap VK).
//!
//! Step `num_chunks` is hardcoded to 1, matching every fixture we currently
//! ship (the mainnet blockchain SNARK and the synthetic ones). Plumb it
//! through if a chunked circuit ever needs it.

use std::env;
use std::fs;
use std::path::Path;

use mina_curves::pasta::{Pallas, Vesta};
use pickles_verifier::serialize::encode_verifier_blob;
use pickles_verifier::wire::parse_wrap_vk;
use poly_commitment::precomputed_srs::get_srs;

fn main() {
    let vk_path =
        env::var("VK_JSON").expect("VK_JSON env var must point to the wrap vk.serde.json");

    println!("cargo::rerun-if-changed={vk_path}");
    println!("cargo::rerun-if-env-changed=VK_JSON");

    let vk_json =
        fs::read_to_string(&vk_path).unwrap_or_else(|e| panic!("failed to read {vk_path}: {e}"));
    let wrap_vk =
        parse_wrap_vk(&vk_json).unwrap_or_else(|e| panic!("failed to parse wrap VK: {e}"));

    let vesta_srs = get_srs::<Vesta>();
    let wrap_srs = get_srs::<Pallas>();

    let blob = encode_verifier_blob(
        &vesta_srs, &wrap_srs, /* step_num_chunks */ 1, &wrap_vk,
    );

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    fs::write(Path::new(&out_dir).join("verifier.bin"), &blob)
        .expect("failed to write verifier.bin");
}
