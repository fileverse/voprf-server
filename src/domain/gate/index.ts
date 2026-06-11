// domain/gate barrel — the interface controllers consume gate logic only through here.
export { getGateDoc } from "./get";
export { registerGateDoc } from "./register";
export type { RegisterOutcome } from "./register";
export { appendEnrollment } from "./enroll";
export type { EnrollOutcome } from "./enroll";
export { revokeGateMember } from "./revoke";
export type { RevokeOutcome } from "./revoke";
export { computeGroupRoot } from "./group";
export { createGateNonce, listLiveNonces, consumeGateNonce } from "./nonce";
export { deriveGateShare } from "./share-derivation";
export {
  isCanonicalDecimalBigInt,
  parseProofShape,
  assertProofScope,
  matchNonceByEncodedMessage,
  assertCurrentRoot,
  assertProofValid,
} from "./proof-verification";
export type { SemaphoreProofShape } from "./proof-verification";
export { validateGateUcan, assertOwnerAuthorized, assertIssuerIsOnChainOwner } from "./owner-auth";
export type { GateAbilitySegment, ValidatedGateUcan } from "./owner-auth";
export { validateVoucherClaims, bindsToAttestedIdentifier } from "./enroll-verification";
export type { VoucherClaims } from "./enroll-verification";
