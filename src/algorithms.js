/** Internal primitive contract table. One algorithm/size is fixed per profile. */
export const signatureByteCeiling = 512;
const sizes = Object.freeze({
  'hmac-sha256': Object.freeze([32]),
  'ecdsa-p256-sha256': Object.freeze([64]),
  'rsa-v1_5-sha256': Object.freeze([256, 384, 512]),
});
export function validSignatureSize(algorithm, size) {
  return typeof algorithm === 'string' && Object.hasOwn(sizes, algorithm) && sizes[algorithm].includes(size);
}
export function keySignatureSize(algorithm, bits) {
  if (!Number.isSafeInteger(bits)) return undefined;
  if (algorithm === 'hmac-sha256' && bits >= 256) return 32;
  if (algorithm === 'ecdsa-p256-sha256' && bits === 256) return 64;
  if (algorithm === 'rsa-v1_5-sha256' && [2048, 3072, 4096].includes(bits)) return bits / 8;
  return undefined;
}
