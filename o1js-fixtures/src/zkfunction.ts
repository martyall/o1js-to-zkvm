// Generate a small ZkFunction (kimchi) proof and dump JSON + VK to
// ../fixtures/o1js-zkfunction/. The output JSON layout is what o1js's
// Experimental.ZkFunction emits in v2.15:
//   { publicInputFields: [...], proof: <base64 of WASM-serialized kimchi proof> }
//
// Unlike ZkProgram (pickles), ZkFunction produces a bare kimchi proof. Native
// Rust verification goes through kimchi::verifier::verify (already a dep of
// pickles-verifier) rather than through pickles_verifier::verify.

import { Experimental, Field } from 'o1js';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, '..', '..', 'fixtures', 'o1js-zkfunction');
mkdirSync(outDir, { recursive: true });

// Pythagoras checker: prove a² + b² = c² with public c.
const pythag = Experimental.ZkFunction({
  name: 'pythagoras',
  publicInputType: Field,
  privateInputTypes: [Field, Field],
  main(c: Field, a: Field, b: Field) {
    const sumSquares = a.mul(a).add(b.mul(b));
    const cSquared = c.mul(c);
    sumSquares.assertEquals(cSquared);
  },
});

console.log('[zkfunction] compiling...');
const { verificationKey } = await pythag.compile();
console.log('[zkfunction] vk obtained');

const a = Field(3);
const b = Field(4);
const c = Field(5);
console.log(`[zkfunction] proving ${a}² + ${b}² = ${c}²`);
const proof = await pythag.prove(c, a, b);
console.log('[zkfunction] proof generated');

const proofJsonObj = proof.toJSON();
writeFileSync(join(outDir, 'proof.json'), JSON.stringify(proofJsonObj, null, 2));
writeFileSync(
  join(outDir, 'verificationKey.json'),
  // KimchiVerificationKey contains BigInts; coerce via String() so we keep
  // the values losslessly without picking a numeric encoding.
  JSON.stringify(verificationKey, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2),
);
writeFileSync(
  join(outDir, 'README.txt'),
  [
    'o1js v2.15 ZkFunction kimchi fixture',
    '',
    'Circuit: pythagoras — publicInput: Field c, privateInput: (Field a, Field b).',
    '  Asserts a² + b² = c². For this fixture: 3, 4, 5.',
    '',
    'Files:',
    '  proof.json            — KimchiProof.toJSON() (publicInputFields + base64 kimchi proof)',
    '  verificationKey.json  — kimchi verifier index (WASM-serialized base64)',
    '',
    'Verification path: kimchi::verifier::verify (NOT pickles_verifier::verify).',
    'See SUMMARY.md for the two-verifier story.',
    '',
    'Regenerate: `npm run generate-zkfunction` from o1js-fixtures/.',
  ].join('\n') + '\n',
);

console.log('[zkfunction] wrote', outDir);
