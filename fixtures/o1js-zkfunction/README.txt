o1js v2.15 ZkFunction kimchi fixture

Circuit: pythagoras — publicInput: Field c, privateInput: (Field a, Field b).
  Asserts a² + b² = c². For this fixture: 3, 4, 5.

Files:
  proof.json            — KimchiProof.toJSON() (publicInputFields + base64 kimchi proof)
  verificationKey.json  — kimchi verifier index (WASM-serialized base64)

Verification path: kimchi::verifier::verify (NOT pickles_verifier::verify).
See SUMMARY.md for the two-verifier story.

Regenerate: `npm run generate-zkfunction` from o1js-fixtures/.
