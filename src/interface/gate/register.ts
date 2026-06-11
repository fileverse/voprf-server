// POST /gate/register — owner-auth against the SUPPLIED anchor (no stored row
// yet), first-writer-wins anchor pin.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { getGateMasterKey } from "../../infra/gate-keys";
import { assertOwnerAuthorized, registerGateDoc } from "../../domain/gate";
import type { GateAcceptedRoot, GateAnchorRef } from "../../infra/database/models";
import { docIdField } from "./validation";

const registerValidation = {
  body: Joi.object({
    docId: docIdField(),
    // .lowercase() is omitted on purpose: under convert:false it would REJECT a
    // mixed-case address rather than coerce it; the controller lowercases instead.
    anchorRef: Joi.object({
      chainId: Joi.number().integer().min(1).max(Number.MAX_SAFE_INTEGER).required(),
      portalAddress: Joi.string()
        .pattern(/^0x[0-9a-fA-F]{40}$/)
        .required(),
      fileId: Joi.number().integer().min(0).max(Number.MAX_SAFE_INTEGER).required(),
    }).required(),
    acceptedRoots: Joi.array()
      .items(
        Joi.object({
          groupRef: Joi.string().required(),
          role: Joi.string().valid("view", "comment").required(),
        })
      )
      .min(1)
      .required(),
    ownerUcan: Joi.string().required(),
  }),
};

async function registerDoc(req: Request, res: Response): Promise<void> {
  const { docId, acceptedRoots, ownerUcan, anchorRef } = req.body as {
    docId: string;
    acceptedRoots: GateAcceptedRoot[];
    ownerUcan: string;
    anchorRef: GateAnchorRef;
  };

  // Fail closed: every accepted root must reference THIS doc's group.
  if (acceptedRoots.some((root) => root.groupRef !== docId)) {
    return throwError({
      code: 400,
      message: GateErrorCode.INVALID_ACCEPTED_ROOTS,
    });
  }

  if (!getGateMasterKey()) {
    return throwError({ code: 503, message: GateErrorCode.MASTER_KEY_NOT_CONFIGURED });
  }

  // Lowercase the portal before storage/owner-auth so the anchor pin compares canonical bytes.
  const anchor: GateAnchorRef = {
    chainId: anchorRef.chainId,
    portalAddress: anchorRef.portalAddress.toLowerCase(),
    fileId: anchorRef.fileId,
  };

  // Owner-auth against the SUPPLIED anchor (no stored row yet).
  await assertOwnerAuthorized(ownerUcan, docId, anchor);

  const outcome = await registerGateDoc(docId, anchor, acceptedRoots);
  if (outcome.kind === "anchor-mismatch") {
    return throwError({
      code: 409,
      message: GateErrorCode.ANCHOR_MISMATCH,
    });
  }

  res.json({ currentEpoch: outcome.currentEpoch });
}

// convert:false: reject string-encoded numbers instead of coercing them.
export default [validate(registerValidation, {}, { convert: false }), registerDoc];
