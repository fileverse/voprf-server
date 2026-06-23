// UCAN validation for the gate (§5.1). Tokens are self-audience (aud = iss =
// ownerDid; there is no gate DID), so there's no delegation chain to walk. We use
// the library directly: ucans.validate() covers signature + time + self-audience,
// ucans.verify() does the capability match; only the issuer→on-chain-owner check
// stays manual (it's an external fact the UCAN can't carry).
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
  hierPart: string,
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

  // Capability check — delegated to @ucans/ucans's own matcher rather than hand-walking
  // payload.att. The token is self-signed by the owner (no proofs), so the required
  // capability is rooted at the token's OWN issuer (rootIssuer = iss). It is deliberately
  // NOT rooted at the on-chain owner: that cross-check stays separate (assertIssuerIs*)
  // so a valid-cap/wrong-owner token fails with NOT_DOC_OWNER, not a generic cap error.
  // Default equalCanDelegate semantics preserve the old strict match (ADMIN ≠ INVITE,
  // exact single segment); the scheme/namespace matching is case-insensitive per the lib.
  const verification = await ucans.verify(token, {
    audience: parsed.payload.aud,
    requiredCapabilities: [
      {
        capability: {
          with: { scheme: "gate", hierPart },
          can: { namespace: "gate", segments: [segment] },
        },
        rootIssuer: parsed.payload.iss,
      },
    ],
  });
  if (!verification.ok) {
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
