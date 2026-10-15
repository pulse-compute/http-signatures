/** HMS contract v1: design types only. No runtime or package exports. */
export type Available<T> =
  | { state: 'available'; value: T }
  | { state: 'unavailable'; reason: 'not-exposed' | 'transformed' | 'not-retained' };
export type Field = { name: string; value: Uint8Array };
export type StructuredFieldType = 'item' | 'list' | 'dictionary';
export type OriginalTarget = {
  form: 'origin' | 'absolute' | 'authority' | 'asterisk' | 'pseudo-headers';
  raw: Uint8Array;
};
export type Target = {
  original: Available<OriginalTarget>;
  uri: Available<string>;
  scheme: Available<string>;
  authority: Available<string>;
  path: Available<string>;
  query: Available<string>;
};
export type Body =
  | { state: 'available'; bytes: Uint8Array }
  | { state: 'unavailable'; reason: 'not-exposed' | 'transformed' | 'not-retained' };
export type MessageCommon = {
  contextId: string;
  direction: 'inbound' | 'outbound';
  trustDomain: string;
  headers: Available<readonly Field[]>;
  trailers: Available<readonly Field[]>;
  body: Body;
};
export type Request = MessageCommon & {
  kind: 'request';
  method: Available<string>;
  target: Target;
};
export type Response = MessageCommon & {
  kind: 'response';
  status: Available<number>;
  associatedRequest: Available<Request>;
};
export type Message = Request | Response;
export type FieldParameter =
  | { name: 'sf' | 'bs' | 'tr' | 'req'; value: true }
  | { name: 'key'; value: string };
export type DerivedParameter =
  | { name: 'req'; value: true }
  | { name: 'name'; value: string };
export type Component =
  | { kind: 'field'; name: string; parameters: readonly FieldParameter[] }
  | { kind: 'derived'; name: '@method' | '@target-uri' | '@authority' | '@scheme'
      | '@request-target' | '@path' | '@query' | '@query-param' | '@status';
      parameters: readonly DerivedParameter[] };
export type Parameter =
  | { name: 'created' | 'expires'; value: number }
  | { name: 'keyid' | 'alg' | 'nonce' | 'tag'; value: string };
export type Limits = {
  envelopeFieldBytes: number; totalFieldBytes: number; fieldValueBytes: number;
  fieldNameBytes: number; fieldCount: number; instancesPerName: number;
  signatures: number; components: number; componentParameters: number;
  signatureParameters: number; metadataStringBytes: number; labelBytes: number;
  targetBytes: number; signatureBaseBytes: number; signatureBytes: number;
  bodyBytes: number; workUnits: number;
  structuredMembers: number; structuredParameters: number;
};
export type Profile = {
  contractVersion: 1;
  id: string;
  label: string;
  context: {
    kind: 'request' | 'response'; direction: 'inbound' | 'outbound';
    trustDomain: string; scheme: 'https'; authority: string;
  };
  requiredComponents: readonly Component[];
  structuredFields: Readonly<Record<string, StructuredFieldType>>;
  allowedAlgorithms: readonly ['hmac-sha256'];
  keyPolicy: { resolverId: string; acceptedKeyIds: readonly string[] };
  time: { requireCreated: true; requireExpires: boolean; maxAgeSeconds: number;
    maxLifetimeSeconds: number; clockSkewSeconds: number };
  requiredTag: string;
  body: { mode: 'required'; algorithm: 'sha-256' } | { mode: 'excluded' };
  replay: { mode: 'required'; namespace: string } | { mode: 'none' };
  limits: Limits;
};
export type FailureCode =
  | 'PROFILE_INVALID' | 'LIMIT_EXCEEDED' | 'MALFORMED_MESSAGE' | 'MALFORMED_SIGNATURE'
  | 'SIGNATURE_NOT_FOUND' | 'UNSUPPORTED_COMPONENT' | 'UNSUPPORTED_ALGORITHM'
  | 'CONTEXT_MISMATCH' | 'COMPONENT_UNAVAILABLE' | 'COMPONENT_MISSING'
  | 'COVERAGE_REQUIRED' | 'METADATA_REQUIRED' | 'TIME_INVALID'
  | 'CAPABILITY_UNAVAILABLE' | 'KEY_REJECTED' | 'SIGNATURE_INVALID'
  | 'BODY_DIGEST_INVALID' | 'REPLAY_REJECTED' | 'OPERATION_FAILED';
export type Result<T> = { ok: true; value: T } | { ok: false; code: FailureCode };
export type KeyIdentity = {
  keyId: string; algorithm: 'hmac-sha256'; trustDomain: string;
  keyVersion: string; keyBits: number;
};
export type Signer = KeyIdentity & {
  sign: (base: Uint8Array) => Promise<Uint8Array>;
};
export type Verifier = KeyIdentity & {
  verify: (base: Uint8Array, signature: Uint8Array) => Promise<boolean>;
};
export type Clock = { nowSeconds: () => number };
export type KeyResolver = {
  id: string;
  resolve: (query: { keyId: string; algorithm: 'hmac-sha256';
    trustDomain: string; profileId: string }) => Promise<Verifier | null>;
};
export type Digest = { sha256: (content: Uint8Array) => Promise<Uint8Array> };
export type ReplayStore = {
  consume: (entry: { namespace: string; profileId: string; trustDomain: string;
    keyId: string; nonce: string; retainUntilSeconds: number }) => Promise<boolean>;
};
export type Signed = { signatureInput: string; signature: string };
export type Verified = {
  contextId: string; profileId: string; label: string;
  keyId: string; keyVersion: string; algorithm: 'hmac-sha256';
  covered: readonly Component[];
  bodyIntegrity: 'verified' | 'not-checked';
  replay: 'consumed' | 'not-checked';
};
export interface Protocol {
  sign(message: Message, options: {
    profile: Profile; covered: readonly Component[]; parameters: readonly Parameter[];
    capabilities: { signer: Signer; clock: Clock; digest?: Digest };
  }): Promise<Result<Signed>>;
  verify(message: Message, options: {
    profile: Profile;
    capabilities: { keys: KeyResolver; clock: Clock; digest?: Digest; replay?: ReplayStore };
  }): Promise<Result<Verified>>;
}
