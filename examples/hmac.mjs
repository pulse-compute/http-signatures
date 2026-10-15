// Complete empty-body GET demonstration using explicit host fixture capabilities.
import { sign, verify } from '@pulse-compute/http-signatures/protocol';
import { message, profile, parameters, signer, clock, receivingProfile, keys, receive } from './hmac-context.mjs';

const signed = await sign(message, {
  profile,
  covered: profile.requiredComponents,
  parameters,
  capabilities: { signer, clock },
});
if (!signed.ok) throw new Error(signed.code);

const signatureHeaders = {
  'Signature-Input': signed.value.signatureInput,
  Signature: signed.value.signature,
};
const received = receive(signatureHeaders);
const checked = await verify(received, {
  profile: receivingProfile,
  capabilities: { keys, clock },
});
if (!checked.ok) throw new Error(checked.code);
console.log(checked.value);
