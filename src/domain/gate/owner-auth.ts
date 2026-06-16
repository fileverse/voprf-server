// UCAN validation for the gate (§5.1). Tokens are self-audience (aud = iss =
// ownerDid; there is no gate DID), so there's no delegation chain to walk —
// ucans.validate() covers signature + time, the capability/issuer checks are manual.
// Capability shape mirrors the client mint: with {scheme:'gate', hierPart:docId},
// can {namespace:'gate', segments:['ADMIN'|'INVITE']}.
import * as ucans from "@ucans/ucans";
import { readOnChainOwnerDid, readOnChainPortalOwnerDid } from "../../infra/chain/portal-reader";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import type { GateAnchorRef } from "../../infra/database/models";

export type GateAbilitySegment = "ADMIN" | "INVITE";

export interface ValidatedGateUcan {
  issuerDid: string;
  facts: Record<string, unknown>[];
}

export const validateGateUcan = async (
  token: string,
  docId: string,
  segment: GateAbilitySegment
): Promise<ValidatedGateUcan> => {
  let parsed: Awaited<ReturnType<typeof ucans.validate>>;
  try {
    parsed = await ucans.validate(token);
  } catch {
    return throwError({ code: 401, message: GateErrorCode.INVALID_UCAN });
  }

  // Self-audience: rejects owner-signed tokens addressed to other services.
  if (parsed.payload.aud !== parsed.payload.iss) {
    return throwError({ code: 401, message: GateErrorCode.INVALID_UCAN });
  }

  const hasCapability = parsed.payload.att.some((capability) => {
    const withPart = capability.with;
    const canPart = capability.can;
    return (
      typeof withPart === "object" &&
      withPart !== null &&
      withPart.scheme === "gate" &&
      withPart.hierPart === docId &&
      typeof canPart === "object" &&
      canPart !== null &&
      canPart.namespace === "gate" &&
      Array.isArray(canPart.segments) &&
      canPart.segments.length === 1 &&
      canPart.segments[0] === segment
    );
  });
  if (!hasCapability) {
    return throwError({ code: 403, message: GateErrorCode.MISSING_CAPABILITY });
  }

  return {
    issuerDid: parsed.payload.iss,
    facts: (parsed.payload.fct ?? []) as Record<string, unknown>[],
  };
};

/** Capability + LIVE on-chain owner cross-check. Never TOFU, never stored. */
export const assertOwnerAuthorized = async (
  token: string,
  docId: string,
  anchorRef: GateAnchorRef
): Promise<string> => {
  const { issuerDid } = await validateGateUcan(token, docId, "ADMIN");
  await assertIssuerIsOnChainOwner(issuerDid, anchorRef, GateErrorCode.NOT_DOC_OWNER);
  return issuerDid;
};

/**
 * INVITE-path owner cross-check: the voucher issuer must be the doc's live
 * on-chain owner. Split from assertOwnerAuthorized so enroll validates the voucher
 * and Privy token before spending the chain read; callers supply the 403 message.
 */
export const assertIssuerIsOnChainOwner = async (
  issuerDid: string,
  anchorRef: GateAnchorRef,
  message: string
): Promise<void> => {
  const ownerDid = await readOnChainOwnerDid(anchorRef);
  if (issuerDid !== ownerDid) {
    throwError({ code: 403, message });
  }
};

/**
 * Group-INVITE-path owner cross-check: the group voucher issuer must be the live
 * on-chain PORTAL owner (personal: the user; team: the workspace ASA). Mirrors
 * assertIssuerIsOnChainOwner but reads the portal owner, not a file owner.
 */
export const assertIssuerIsOnChainPortalOwner = async (
  issuerDid: string,
  anchorRef: GateAnchorRef,
  message: string
): Promise<void> => {
  const ownerDid = await readOnChainPortalOwnerDid(anchorRef);
  if (issuerDid !== ownerDid) {
    throwError({ code: 403, message });
  }
};

/**
 * Group admin (register/revoke) authorization: capability (gate/ADMIN on the
 * groupRef hierPart) + LIVE on-chain PORTAL owner cross-check. The validateGateUcan
 * `docId` param is really the hierPart resource-id — for groups it's the groupRef.
 */
export const assertGroupOwnerAuthorized = async (
  token: string,
  groupRef: string,
  anchorRef: GateAnchorRef
): Promise<string> => {
  const { issuerDid } = await validateGateUcan(token, groupRef, "ADMIN");
  await assertIssuerIsOnChainPortalOwner(issuerDid, anchorRef, GateErrorCode.NOT_DOC_OWNER);
  return issuerDid;
};
