// POST /gate/group/:groupRef/enroll — full chain: group exists → Privy verify →
// group voucher claims → issuer === on-chain PORTAL owner (stored anchor) → BIND →
// PIN+ADD. Mirrors enroll.ts; the owner cross-check reads the PORTAL owner.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { verifyIdentityToken } from "../../infra/privy";
import {
  appendGroupEnrollment,
  assertIssuerIsOnChainPortalOwner,
  bindsToAttestedIdentifier,
  getGateGroup,
  validateGroupVoucherClaims,
} from "../../domain/gate";
import { commitmentField } from "./validation";

const groupEnrollValidation = {
  body: Joi.object({
    voucher: Joi.string().required(),
    commitment: commitmentField(),
    privyIdToken: Joi.string().required(),
  }),
};

async function enrollGroupMember(req: Request, res: Response): Promise<void> {
  const groupRef = req.params.groupRef;
  const { voucher, commitment, privyIdToken } = req.body as {
    voucher: string;
    commitment: string;
    privyIdToken: string;
  };

  const group = await getGateGroup(groupRef);
  if (!group) return throwError({ code: 404, message: GateErrorCode.GROUP_NOT_REGISTERED });

  const identifiers = await verifyIdentityToken(privyIdToken);
  const { issuerDid, claims } = await validateGroupVoucherClaims(voucher, groupRef);
  await assertIssuerIsOnChainPortalOwner(issuerDid, group.anchorRef, GateErrorCode.NOT_DOC_OWNER);
  // Empty identifiers naturally fail the BIND → 403.
  if (!bindsToAttestedIdentifier(identifiers, claims.salt, claims.idHash)) {
    return throwError({ code: 403, message: GateErrorCode.BIND_MISMATCH });
  }

  const outcome = await appendGroupEnrollment(groupRef, claims.idHash, commitment, claims.role);
  if (outcome === "unknown-doc") return throwError({ code: 404, message: GateErrorCode.GROUP_NOT_REGISTERED });
  if (outcome === "revoked") {
    return throwError({ code: 403, message: GateErrorCode.IDENTITY_REVOKED });
  }
  if (outcome === "pin-conflict") {
    return throwError({
      code: 409,
      message: GateErrorCode.COMMITMENT_PINNED,
    });
  }
  res.status(204).end();
}

// convert:false: uniform with the other gate schemas.
export default [validate(groupEnrollValidation, {}, { convert: false }), enrollGroupMember];
