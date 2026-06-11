// POST /gate/enroll — full chain: Privy verify → voucher claims → issuer ===
// on-chain owner (stored anchor) → BIND → PIN+ADD.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { verifyIdentityToken } from "../../infra/privy";
import {
  appendEnrollment,
  assertIssuerIsOnChainOwner,
  bindsToAttestedIdentifier,
  getGateDoc,
  validateVoucherClaims,
} from "../../domain/gate";
import { commitmentField, docIdField } from "./validation";

const enrollValidation = {
  body: Joi.object({
    docId: docIdField(),
    voucher: Joi.string().required(),
    commitment: commitmentField(),
    privyIdToken: Joi.string().required(),
  }),
};

async function enrollMember(req: Request, res: Response): Promise<void> {
  const { docId, voucher, commitment, privyIdToken } = req.body as {
    docId: string;
    voucher: string;
    commitment: string;
    privyIdToken: string;
  };

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  const identifiers = await verifyIdentityToken(privyIdToken);
  const { issuerDid, claims } = await validateVoucherClaims(voucher, docId);
  await assertIssuerIsOnChainOwner(issuerDid, doc.anchorRef, GateErrorCode.NOT_DOC_OWNER);
  // Empty identifiers naturally fail the BIND → 403.
  if (!bindsToAttestedIdentifier(identifiers, claims.salt, claims.idHash)) {
    return throwError({ code: 403, message: GateErrorCode.BIND_MISMATCH });
  }

  const outcome = await appendEnrollment(docId, claims.idHash, commitment, claims.role);
  if (outcome === "unknown-doc") return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  if (outcome === "pin-conflict") {
    return throwError({
      code: 409,
      message: GateErrorCode.COMMITMENT_PINNED,
    });
  }
  res.status(204).end();
}

// convert:false: uniform with the other gate schemas.
export default [validate(enrollValidation, {}, { convert: false }), enrollMember];
