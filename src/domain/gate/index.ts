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
  assertRootInSet,
  assertProofValid,
} from "./proof-verification";
export type { SemaphoreProofShape } from "./proof-verification";

// Standalone reusable groups (groups-semaphore Phase 1).
export { getGateGroup } from "./group-get";
export { registerGateGroup } from "./group-register";
export type { GroupRegisterOutcome } from "./group-register";
export { appendGroupEnrollment } from "./group-enroll";
export { revokeGateGroupMember } from "./group-revoke";
export type { GroupRevokeOutcome } from "./group-revoke";
export { attachGroupToDoc, detachGroupFromDoc } from "./group-attach";
export type { AttachOutcome } from "./group-attach";
export { resolveAcceptedRoots } from "./resolve-roots";
export {
  validateGateUcan,
  assertOwnerAuthorized,
  assertIssuerIsOnChainOwner,
  assertIssuerIsOnChainPortalOwner,
  assertGroupOwnerAuthorized,
} from "./owner-auth";
export type { GateAbilitySegment, ValidatedGateUcan } from "./owner-auth";
export { validateVoucherClaims, validateGroupVoucherClaims, bindsToAttestedIdentifier } from "./enroll-verification";
export type { VoucherClaims } from "./enroll-verification";
