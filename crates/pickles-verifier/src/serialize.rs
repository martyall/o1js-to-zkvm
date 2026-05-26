//! Blob format for shipping a [`Verifier`] into the SP1 guest.
//!
//! Mostly zero-parse: the heavy data (SRS generators + the wrap blinder `h`)
//! is laid out as bit-identical pod arrays the guest reinterprets via
//! `bytemuck`; the lighter `wrap_vk` rides in via kimchi's own serde over
//! `postcard`.
//!
//! Blob layout (all little-endian, sections 8-byte aligned at start):
//!
//! ```text
//! offset  field                          bytes
//! ----    -----                          -----
//! 0       vesta_g_len: u64               8
//! 8       PodVesta * vesta_g_len         72 * vesta_g_len     -- vesta SRS .g
//! ...     wrap_g_len: u64                8
//! +8      PodPallas * wrap_g_len         72 * wrap_g_len      -- wrap SRS .g
//! ...     wrap_h: PodPallas              72                   -- wrap SRS .h
//! ...     step_num_chunks: u64           8
//! ...     wrap_vk_len: u64               8
//! +8      bytes * wrap_vk_len            wrap_vk_len          -- postcard(wrap_vk); srs is #[serde(skip)]
//! ```
//!
//! The decoder gets 8-byte alignment from a `#[repr(C, align(8))]` wrapper
//! around `include_bytes!` at the guest call site. Soundness of the
//! [`PodVesta`] / [`PodPallas`] -> `Vesta` / `Pallas` slice casts depends on
//! the Pod structs being bit-identical to arkworks's affine layout for the
//! pinned versions; the [`tests`] module pins it.
//!
//! TODO: the wrap SRS's Lagrange basis is **not** precomputed in the blob
//! (kimchi's `lagrange_bases` field is private; populating it would need an
//! upstream API). The guest pays an on-the-fly recomputation in
//! `batch_verify_with_rng`'s public-input commitment — significant SP1 cycles
//! that an upstream `SRS::add_lagrange_basis(domain_size, basis)` (or similar)
//! would let us amortize at build time.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::{Pod, Zeroable};
use mina_curves::pasta::{Pallas, Vesta};

use crate::types::{Verifier, VestaSrs, WrapSrs, WrapVerifierIndex};

// ---------------------------------------------------------------------------
// Pod-layout structs for the Pasta affine points.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct PodVesta {
    pub x: [u64; 4],
    pub y: [u64; 4],
    pub infinity: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct PodPallas {
    pub x: [u64; 4],
    pub y: [u64; 4],
    pub infinity: u8,
    pub _pad: [u8; 7],
}

fn vesta_to_pod(v: &Vesta) -> PodVesta {
    PodVesta {
        x: v.x.0 .0,
        y: v.y.0 .0,
        infinity: u8::from(v.infinity),
        _pad: [0; 7],
    }
}

fn pallas_to_pod(v: &Pallas) -> PodPallas {
    PodPallas {
        x: v.x.0 .0,
        y: v.y.0 .0,
        infinity: u8::from(v.infinity),
        _pad: [0; 7],
    }
}

// ---------------------------------------------------------------------------
// Section primitives.
// ---------------------------------------------------------------------------

fn write_u64_le(out: &mut Vec<u8>, x: u64) {
    out.extend_from_slice(&x.to_le_bytes());
}

fn write_vesta_section(out: &mut Vec<u8>, points: &[Vesta]) {
    let pods: Vec<PodVesta> = points.iter().map(vesta_to_pod).collect();
    write_u64_le(out, pods.len() as u64);
    out.extend_from_slice(bytemuck::cast_slice(&pods));
}

fn write_pallas_section(out: &mut Vec<u8>, points: &[Pallas]) {
    let pods: Vec<PodPallas> = points.iter().map(pallas_to_pod).collect();
    write_u64_le(out, pods.len() as u64);
    out.extend_from_slice(bytemuck::cast_slice(&pods));
}

fn write_one_pallas(out: &mut Vec<u8>, p: &Pallas) {
    let pod = pallas_to_pod(p);
    out.extend_from_slice(bytemuck::bytes_of(&pod));
}

fn write_bytes_section(out: &mut Vec<u8>, bytes: &[u8]) {
    write_u64_le(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn read_u64_le(bytes: &[u8]) -> (u64, &[u8]) {
    assert!(bytes.len() >= 8, "blob truncated reading u64");
    let (head, rest) = bytes.split_at(8);
    (u64::from_le_bytes(head.try_into().unwrap()), rest)
}

fn read_vesta_section(bytes: &[u8]) -> (&[Vesta], &[u8]) {
    let (len, rest) = read_u64_le(bytes);
    let len = len as usize;
    let byte_len = len.checked_mul(size_of::<PodVesta>()).expect("section overflow");
    assert!(rest.len() >= byte_len, "blob truncated mid vesta section");
    let (section, tail) = rest.split_at(byte_len);
    let pods: &[PodVesta] = bytemuck::cast_slice(section);
    // SAFETY: PodVesta is `#[repr(C)]` and bit-identical to mina-curves's Vesta
    // affine for the pinned arkworks version (checked by the layout tests).
    let vestas: &[Vesta] =
        unsafe { core::slice::from_raw_parts(pods.as_ptr() as *const Vesta, pods.len()) };
    (vestas, tail)
}

fn read_pallas_section(bytes: &[u8]) -> (&[Pallas], &[u8]) {
    let (len, rest) = read_u64_le(bytes);
    let len = len as usize;
    let byte_len = len.checked_mul(size_of::<PodPallas>()).expect("section overflow");
    assert!(rest.len() >= byte_len, "blob truncated mid pallas section");
    let (section, tail) = rest.split_at(byte_len);
    let pods: &[PodPallas] = bytemuck::cast_slice(section);
    // SAFETY: PodPallas is `#[repr(C)]` and bit-identical to mina-curves's
    // Pallas affine for the pinned arkworks version.
    let pallases: &[Pallas] =
        unsafe { core::slice::from_raw_parts(pods.as_ptr() as *const Pallas, pods.len()) };
    (pallases, tail)
}

fn read_one_pallas(bytes: &[u8]) -> (Pallas, &[u8]) {
    let byte_len = size_of::<PodPallas>();
    assert!(bytes.len() >= byte_len, "blob truncated reading one Pallas");
    let (section, tail) = bytes.split_at(byte_len);
    let pod: &PodPallas = bytemuck::from_bytes(section);
    // SAFETY: same as `read_pallas_section`.
    let p = unsafe { *(pod as *const PodPallas as *const Pallas) };
    (p, tail)
}

fn read_bytes_section(bytes: &[u8]) -> (&[u8], &[u8]) {
    let (len, rest) = read_u64_le(bytes);
    let len = len as usize;
    assert!(rest.len() >= len, "blob truncated mid bytes section");
    rest.split_at(len)
}

// ---------------------------------------------------------------------------
// Public encode / decode.
// ---------------------------------------------------------------------------

/// Encode a [`Verifier`]'s shippable form: pod-cast SRS data + postcard'd
/// wrap VK.
pub fn encode_verifier_blob(
    vesta_srs: &VestaSrs,
    wrap_srs: &WrapSrs,
    step_num_chunks: usize,
    wrap_vk: &WrapVerifierIndex,
) -> Vec<u8> {
    let mut out = Vec::new();
    write_vesta_section(&mut out, &vesta_srs.g);
    write_pallas_section(&mut out, &wrap_srs.g);
    write_one_pallas(&mut out, &wrap_srs.h);
    write_u64_le(&mut out, step_num_chunks as u64);
    let vk_bytes = postcard::to_allocvec(wrap_vk).expect("postcard(wrap_vk)");
    write_bytes_section(&mut out, &vk_bytes);
    out
}

/// Decode the blob produced by [`encode_verifier_blob`] into a fully-assembled
/// [`Verifier`], suitable to hand straight to [`crate::verify`].
///
/// `bytes` must be 8-byte aligned (the guest gets this from a
/// `#[repr(C, align(8))]` wrapper around `include_bytes!`). `no_std`.
pub fn decode_verifier_blob(bytes: &[u8]) -> Verifier {
    let (vesta_g, rest) = read_vesta_section(bytes);
    let (wrap_g, rest) = read_pallas_section(rest);
    let (wrap_h, rest) = read_one_pallas(rest);
    let (step_num_chunks, rest) = read_u64_le(rest);
    let (vk_bytes, _tail) = read_bytes_section(rest);

    // Vesta SRS: only `g` is read on the verify path (the stage-2 accumulator
    // MSM). `h` and lagrange basis are not exercised here.
    let mut vesta_srs = VestaSrs::default();
    vesta_srs.g = vesta_g.to_vec();

    // Wrap (Pallas) SRS: `g` + `h`. The Lagrange basis is left empty;
    // kimchi recomputes it on demand inside `batch_verify_with_rng`'s
    // public-input commitment (see the module-level TODO).
    let mut wrap_srs = WrapSrs::default();
    wrap_srs.g = wrap_g.to_vec();
    wrap_srs.h = wrap_h;

    let wrap_vk: WrapVerifierIndex =
        postcard::from_bytes(vk_bytes).expect("postcard wrap_vk decode");
    Verifier::new(
        wrap_vk,
        Arc::new(wrap_srs),
        Arc::new(vesta_srs),
        step_num_chunks as usize,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::align_of;

    /// Pod structs match the size + alignment we encode.
    #[test]
    fn pod_layouts_are_8_byte_aligned_72_bytes() {
        assert_eq!(size_of::<PodVesta>(), 72);
        assert_eq!(size_of::<PodPallas>(), 72);
        assert_eq!(align_of::<PodVesta>(), 8);
        assert_eq!(align_of::<PodPallas>(), 8);
    }

    /// PodVesta is bit-identical to Vesta affine for the pinned arkworks
    /// version (the unsafe slice cast depends on this).
    #[test]
    fn pod_vesta_size_matches_vesta() {
        assert_eq!(size_of::<PodVesta>(), size_of::<Vesta>());
        assert_eq!(align_of::<PodVesta>(), align_of::<Vesta>());
    }

    #[test]
    fn pod_pallas_size_matches_pallas() {
        assert_eq!(size_of::<PodPallas>(), size_of::<Pallas>());
        assert_eq!(align_of::<PodPallas>(), align_of::<Pallas>());
    }
}
