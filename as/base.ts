// RFC 9421 section 2.5: ordered component lines and one final parameters line.
// Component identifiers and values have already passed the narrow profile checks.
export function signatureBase(identifiers: string[], values: string[], parameters: string): string {
  let result = '';
  for (let i = 0; i < identifiers.length; i++) result += identifiers[i] + ': ' + values[i] + '\n';
  return result + '"@signature-params": ' + parameters;
}
