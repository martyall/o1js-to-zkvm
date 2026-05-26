//! Blob format for shipping a [`Verifier`] into the SP1 guest.
//!
//! Mostly zero-parse: the heavy data (SRS generators, the wrap blinder `h`,
//! and the wrap SRS's **Lagrange basis** at the wrap proof's domain) is laid
//! out as bit-identical pod arrays the guest reinterprets via `bytemuck`; the
//! lighter `wrap_vk` rides in via kimchi's own serde over `postcard`.
//!
//! Baking the Lagrange basis matters. The wrap proof's public-input
//! commitment in `batch_verify_with_rng` calls `srs.get_lagrange_basis(domain)`;
//! without a pre-seeded cache, kimchi runs the FFT-on-curve generator on the
//! full SRS — historically ~91% of the guest's cycles. Encode-side we compute
//! it once via [`poly_commitment::SRS::get_lagrange_basis_from_domain_size`];
//! decode-side we seed the cache via the public `SRS::lagrange_bases()`
//! accessor (the *field* is private, the accessor is not).
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
//! ...     wrap_basis_len: u64            8
//! +8      PodPallas * wrap_basis_len     72 * wrap_basis_len  -- wrap Lagrange basis
//! ...                                                            (one Pallas per single-chunk PolyComm)
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
//! Single-chunk Lagrange basis: we assert each `PolyComm` has `chunks.len()
//! == 1` at encode time. This holds whenever `wrap_srs.g.len() >=
//! wrap_vk.domain.size()`, which is always the case for our circuits (wrap
//! SRS = 2¹⁵; wrap domain ≤ 2¹⁵).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::{Pod, Zeroable};
use mina_curves::pasta::{Pallas, Vesta};
use poly_commitment::commitment::PolyComm;
// Bring the `poly_commitment::SRS` trait into scope so we can call
// `get_lagrange_basis_from_domain_size` on the IPA SRS at encode time.
use poly_commitment::SRS as _;

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
    let byte_len = len
        .checked_mul(size_of::<PodVesta>())
        .expect("section overflow");
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
    let byte_len = len
        .checked_mul(size_of::<PodPallas>())
        .expect("section overflow");
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
// Lagrange basis seeding.
// ---------------------------------------------------------------------------

/// Seed the wrap SRS's Lagrange-basis cache at `domain_size`. Interior
/// mutability via the public `SRS::lagrange_bases()` accessor, so this works
/// through a shared `&WrapSrs` (i.e. through an `Arc<WrapSrs>` deref).
///
/// std and no_std take different cache shapes: in std, poly-commitment's
/// `HashMapCache` (`Arc<Mutex<HashMap<K, Arc<V>>>>`) with `set_once(K, V)`;
/// in no_std, a plain `Rc<RefCell<HashMap<K, Rc<V>>>>` with
/// `borrow_mut().insert(K, Rc::new(V))`. We always insert (overwriting any
/// existing entry) — fine because the basis is deterministic in the SRS and
/// domain.
fn seed_wrap_lagrange_basis(srs: &WrapSrs, domain_size: usize, basis: Vec<PolyComm<Pallas>>) {
    #[cfg(feature = "std")]
    {
        srs.lagrange_bases().set_once(domain_size, basis);
    }
    #[cfg(not(feature = "std"))]
    {
        srs.lagrange_bases()
            .borrow_mut()
            .insert(domain_size, alloc::rc::Rc::new(basis));
    }
}

// ---------------------------------------------------------------------------
// Public encode / decode.
// ---------------------------------------------------------------------------

/// Encode a [`Verifier`]'s shippable form: pod-cast SRS data + pre-computed
/// wrap Lagrange basis + postcard'd wrap VK.
///
/// Internally invokes `wrap_srs.get_lagrange_basis_from_domain_size(domain_size)`
/// with `domain_size = wrap_vk.domain.size()`. Each `PolyComm` in the basis is
/// asserted single-chunk (it is, for any of our wrap circuits).
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

    // Pre-compute the wrap SRS's Lagrange basis at the wrap proof's domain
    // and inline it. The Deref'd `Vec<PolyComm<Pallas>>` view lives only as
    // long as the temporary; copy out each single-chunk Pallas point.
    let domain_size = wrap_vk.domain.size as usize;
    let basis_ref = wrap_srs.get_lagrange_basis_from_domain_size(domain_size);
    let basis: &[PolyComm<Pallas>] = &basis_ref;
    let mut basis_points: Vec<Pallas> = Vec::with_capacity(basis.len());
    for (i, poly) in basis.iter().enumerate() {
        assert_eq!(
            poly.chunks.len(),
            1,
            "wrap lagrange basis poly {i}: expected single-chunk PolyComm, got {} chunks",
            poly.chunks.len()
        );
        basis_points.push(poly.chunks[0]);
    }
    write_pallas_section(&mut out, &basis_points);

    write_u64_le(&mut out, step_num_chunks as u64);
    let vk_bytes = postcard::to_allocvec(wrap_vk).expect("postcard(wrap_vk)");
    write_bytes_section(&mut out, &vk_bytes);
    out
}

/// Decode the blob produced by [`encode_verifier_blob`] into a fully-assembled
/// [`Verifier`], suitable to hand straight to [`crate::verify`]. The wrap
/// Lagrange basis is decoded and seeded into the wrap SRS's cache so kimchi
/// will hit the cache and skip the FFT-on-curve generator.
///
/// `bytes` must be 8-byte aligned (the guest gets this from a
/// `#[repr(C, align(8))]` wrapper around `include_bytes!`). `no_std`.
pub fn decode_verifier_blob(bytes: &[u8]) -> Verifier {
    let (vesta_g, rest) = read_vesta_section(bytes);
    let (wrap_g, rest) = read_pallas_section(rest);
    let (wrap_h, rest) = read_one_pallas(rest);
    let (wrap_basis_pts, rest) = read_pallas_section(rest);
    let (step_num_chunks, rest) = read_u64_le(rest);
    let (vk_bytes, _tail) = read_bytes_section(rest);

    // Vesta SRS: only `g` is read on the verify path (the stage-2 accumulator
    // MSM). `h` and lagrange basis are not exercised here.
    let mut vesta_srs = VestaSrs::default();
    vesta_srs.g = vesta_g.to_vec();

    // Wrap (Pallas) SRS: `g` + `h`. Lagrange basis is seeded below.
    let mut wrap_srs = WrapSrs::default();
    wrap_srs.g = wrap_g.to_vec();
    wrap_srs.h = wrap_h;

    let wrap_vk: WrapVerifierIndex =
        postcard::from_bytes(vk_bytes).expect("postcard wrap_vk decode");

    // Rebuild the single-chunk PolyComm vector from the bare Pallas points and
    // seed at the wrap proof's domain size. We trust the encoded basis_len to
    // equal `wrap_vk.domain.size()` (encoder uses the same value); the cache
    // key is derived from the VK, so any mismatch surfaces as a cache miss +
    // on-the-fly fallback rather than wrong output.
    let basis: Vec<PolyComm<Pallas>> = wrap_basis_pts
        .iter()
        .map(|p| PolyComm {
            chunks: alloc::vec![*p],
        })
        .collect();
    let domain_size = wrap_vk.domain.size as usize;

    let wrap_srs_arc = Arc::new(wrap_srs);
    seed_wrap_lagrange_basis(&wrap_srs_arc, domain_size, basis);

    Verifier::new(
        wrap_vk,
        wrap_srs_arc,
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
