# o1js fixture generators

Node project that uses `o1js@2.15.0` to produce reference proofs in the two
shapes the SDK exposes:

- **`src/zkprogram.ts`** — `ZkProgram` (pickles). Writes to `../fixtures/o1js-zkprogram/`.
- **`src/zkfunction.ts`** — `Experimental.ZkFunction` (bare kimchi). Writes to `../fixtures/o1js-zkfunction/`.

## Regenerate

```sh
cd o1js-fixtures
npm install
npm run generate         # both
# or
npm run generate-zkprogram
npm run generate-zkfunction
```

## Format findings (M7)

Two different on-wire encodings inside the base64 payload — material for the
Rust ingestion paths:

### ZkProgram (`proof.json` → `proof` field)

base64 of **OCaml S-expression text** for `Pickles.Proof.t`. Decoded:

```
((statement((proof_state((deferred_values((plonk((alpha((inner(d1bf… 19f7…))))))…
```

This is what o1js's `Pickles.proofToBase64` produces — NOT bin_prot. The
internal type tree mirrors the same `Pickles.Proof.Proofs_verified_2.Repr.Stable.V2`
shape `mina_p2p_messages` decodes, but the wire serialization is sexpr, not
bin_prot. Atomic field-element encoding is LE-hex 64-bit limbs (e.g.
`d1bf4da023ceaf65 19f7e59422edfe46` is two LE u64 limbs of a 128-bit challenge).

Verification path → `pickles_verifier::verify` (pickles).

### ZkFunction (`proof.json` → `proof` field)

base64 of a **binary kimchi proof** from `WasmFpProverProof.serialize()`
(o1js's WASM bindings around the upstream kimchi crate). The decoded bytes
are kimchi's internal compressed encoding — different from the kimchi
Rust-serde JSON form `pickles-verifier`'s `wire::parse_wrap_proof` consumes.

Verification path → upstream `kimchi::verifier::verify` (kimchi, NOT pickles).

## Implications for `pickles-verifier::ingest::o1js`

The naive expectation (covered in the original plan) was that o1js's `proof`
field is base64 of the same bin_prot the daemon serves, so the bin_prot
adapter would handle both paths. **That's not the case** — see findings
above. Concrete work needed:

1. **OCaml S-expr parser** for the ZkProgram path. Structurally parallel to
   the existing `wire::OcamlProof::parse` (OCaml-yojson) but in S-expr
   syntax. Field-element encoding is LE-hex limbs (similar to the
   existing `wire::combine_limbs_le`). After parsing, the same
   `OcamlProof::into_verifiable` recipe applies.
2. **Real `Pickles.Dummy.Ipa.Wrap.sg` constant**. The current `ingest::bin_prot`
   converter has a placeholder (curve identity) — sufficient for the
   `mpv = 2` case (mainnet blockchain SNARK) but wrong for the `mpv = 0`
   case ZkProgram proofs produce. Compute via the OCaml derivation
   (`Common.dummy_sg_from_seed` with the "wrap" tag).
3. **Kimchi WASM binary decoder** for the ZkFunction path. Either reverse-
   engineer the wasm-serialization format, or call kimchi's existing
   deserializer if one exists for that wire form.

None of these is part of this PR; all are explicit TODOs in `SUMMARY.md`.
