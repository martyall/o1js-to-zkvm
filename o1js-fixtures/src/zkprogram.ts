// Generate a small ZkProgram (pickles) proof and dump JSON + VK to
// ../fixtures/o1js-zkprogram/. The output JSON layout is what o1js's
// Proof.toJSON() emits in v2.15:
//   { publicInput: [...], publicOutput: [...], maxProofsVerified, proof }
// where `proof` is base64 of OCaml Pickles.Proof.t bin_prot — the same
// encoding the Mina daemon serves for blockchain state proofs.
//
// The chosen circuit is a single-method ZkProgram that takes a Field and
// proves `out = in + in` (so the public output is 2 * publicInput[0]). Small
// enough to compile + prove quickly; gives us a non-trivial pickles proof
// to feed pickles-verifier::ingest::o1js.

import { Field, ZkProgram } from 'o1js';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, '..', '..', 'fixtures', 'o1js-zkprogram');
mkdirSync(outDir, { recursive: true });

const Adder = ZkProgram({
  name: 'adder',
  publicInput: Field,
  publicOutput: Field,
  methods: {
    double: {
      privateInputs: [],
      async method(x: Field) {
        return { publicOutput: x.add(x) };
      },
    },
  },
});

console.log('[zkprogram] compiling...');
const { verificationKey } = await Adder.compile();
console.log('[zkprogram] vk.hash =', verificationKey.hash.toString());

const x = Field(7);
console.log('[zkprogram] proving x =', x.toString());
const { proof } = await Adder.double(x);
console.log('[zkprogram] proof generated, maxProofsVerified =', proof.maxProofsVerified);

const proofJsonObj = proof.toJSON();
writeFileSync(join(outDir, 'proof.json'), JSON.stringify(proofJsonObj, null, 2));
writeFileSync(
  join(outDir, 'verificationKey.json'),
  JSON.stringify(
    { data: verificationKey.data, hash: verificationKey.hash.toString() },
    null,
    2,
  ),
);
writeFileSync(
  join(outDir, 'README.txt'),
  [
    'o1js v2.15 ZkProgram pickles fixture',
    '',
    'Circuit: `Adder.double` — publicInput: Field, publicOutput: Field.',
    `  Input  publicInput  = ${x.toString()}`,
    `  Output publicOutput = ${x.add(x).toString()}`,
    '',
    'Files:',
    '  proof.json            — Proof.toJSON() (publicInput + publicOutput + maxProofsVerified + base64 bin_prot proof)',
    '  verificationKey.json  — { data: base64 bin_prot, hash: decimal Fp }',
    '',
    'Regenerate: `npm run generate-zkprogram` from o1js-fixtures/.',
  ].join('\n') + '\n',
);

console.log('[zkprogram] wrote', outDir);
