import { readFile } from 'node:fs/promises';
import { parseSignatureInput, parseSignatureEnvelope, serializeSignatureInput } from '../src/signature-fields.js';
const rfc = JSON.parse(await readFile(new URL('../test/fixtures/signature-fields.json', import.meta.url))).rfcB25;
const dense = Array.from({ length: 8 }, (_, i) => 's' + i + '=(' +
  Array.from({ length: 32 }, (_, j) => '"x' + j + '";sf;req;tr').join(' ') +
  ');created=1;keyid="fixture"').join(', ');
const cases = [];
for (const [name, input] of [
  ['B.2.5 input', rfc.signatureInput],
  ['full 16384-byte field', 'a=()'.padEnd(16384, ' ')],
  ['8 signatures x 32 parameterized components', dense],
]) {
  const parsed = parseSignatureInput(input);
  if (!parsed.ok) throw Error(JSON.stringify(parsed));
  const serialized = serializeSignatureInput(parsed.value);
  if (!serialized.ok) throw Error(JSON.stringify(serialized));
  cases.push({ name, inputBytes: input.length, parseWorkUnits: parsed.workUnits,
    serializedBytes: serialized.value.length, serializeWorkUnits: serialized.workUnits });
}
const envelope = parseSignatureEnvelope({ signatureInput: rfc.signatureInput, signature: rfc.signature });
if (!envelope.ok) throw Error(JSON.stringify(envelope));
console.log(JSON.stringify({ runtime: process.version,
  scope: 'Logical budget counters only; no CPU or memory limit claim',
  envelopeB25WorkUnits: envelope.workUnits, cases }, null, 2));
