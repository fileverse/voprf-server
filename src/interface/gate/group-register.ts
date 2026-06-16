// POST /gate/group/register — owner-auth against the SUPPLIED portal anchor (no
// stored row yet), first-writer-wins anchor pin. Mirrors register.ts.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { assertGroupOwnerAuthorized, registerGateGroup } from "../../domain/gate";
import type { GateAnchorRef } from "../../infra/database/models";
import { groupRefField } from "./validation";

const groupRegisterValidation = {
  body: Joi.object({
    groupRef: groupRefField(),
    // .lowercase() is omitted on purpose: under convert:false it would REJECT a
    // mixed-case address rather than coerce it; the controller lowercases instead.
    anchorRef: Joi.object({
      chainId: Joi.number().integer().min(1).max(Number.MAX_SAFE_INTEGER).required(),
      portalAddress: Joi.string()
        .pattern(/^0x[0-9a-fA-F]{40}$/)
        .required(),
      // fileId is unused for a group (owner-auth reads the portal owner) — default 0.
      fileId: Joi.number().integer().min(0).max(Number.MAX_SAFE_INTEGER).default(0),
    }).required(),
    ownerUcan: Joi.string().required(),
  }),
};

async function registerGroup(req: Request, res: Response): Promise<void> {
  const { groupRef, ownerUcan, anchorRef } = req.body as {
    groupRef: string;
    ownerUcan: string;
    anchorRef: GateAnchorRef;
  };

  // Lowercase the portal before storage/owner-auth so the anchor pin AND the
  // cross-portal attach compare canonical bytes (getAddress normalizes internally,
  // but the stored portalAddress is a raw string-compare basis — must match register.ts).
  const anchor: GateAnchorRef = {
    chainId: anchorRef.chainId,
    portalAddress: anchorRef.portalAddress.toLowerCase(),
    fileId: anchorRef.fileId,
  };

  // Owner-auth against the SUPPLIED portal anchor (no stored row yet).
  await assertGroupOwnerAuthorized(ownerUcan, groupRef, anchor);

  const outcome = await registerGateGroup(groupRef, anchor);
  if (outcome.kind === "anchor-mismatch") {
    return throwError({
      code: 409,
      message: GateErrorCode.GROUP_ANCHOR_MISMATCH,
    });
  }

  res.json({ ok: true });
}

// convert:false: reject string-encoded numbers instead of coercing them.
export default [validate(groupRegisterValidation, {}, { convert: false }), registerGroup];
