// POST /gate/register — owner-auth against the SUPPLIED anchor (no stored row
// yet), first-writer-wins anchor pin.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { logger } from "../../logger";
import { getGateMasterKey } from "../../infra/gate-keys";
import { assertCollaboratorAuthorized, getGateGroup, registerGateDoc, verifyIdentityUcan } from "../../domain/gate";
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
          role: Joi.string().valid("view", "comment", "edit").required(),
        })
      )
      .min(1)
      .required(),
    ownerUcan: Joi.string().required(),
    // Optional: binds the doc to the creator's identity contract (immutable). Legacy
    // clients omit it → the doc stays collaborator-auth only (no identity enforcement).
    identityUcan: Joi.string(),
  }),
};

async function registerDoc(req: Request, res: Response): Promise<void> {
  const { docId, acceptedRoots, ownerUcan, anchorRef, identityUcan } = req.body as {
    docId: string;
    acceptedRoots: GateAcceptedRoot[];
    ownerUcan: string;
    anchorRef: GateAnchorRef;
    identityUcan?: string;
  };

  // Fail closed: every accepted root must reference THIS doc's own implicit group
  // (groupRef === docId, always allowed) OR a previously-registered named group on the
  // SAME host portal (cross-portal rule, mirroring attach.ts — otherwise the owner could
  // route a foreign portal's group root onto their doc).
  const nonSelfRefs = [...new Set(acceptedRoots.map((root) => root.groupRef).filter((ref) => ref !== docId))];
  for (const groupRef of nonSelfRefs) {
    const group = await getGateGroup(groupRef);
    if (!group) {
      return throwError({
        code: 400,
        message: GateErrorCode.INVALID_ACCEPTED_ROOTS,
      });
    }
    // Stored portals are lowercased at group-register; lowercase the incoming side so the
    // comparison is byte-canonical (the body's portalAddress is not yet normalized here).
    if (group.anchorRef.portalAddress !== anchorRef.portalAddress.toLowerCase()) {
      return throwError({ code: 403, message: GateErrorCode.CROSS_PORTAL_ATTACH });
    }
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
  await assertCollaboratorAuthorized(ownerUcan, docId, anchor);

  // Capture the creator's identity binding at first-write (immutable in registerGateDoc). A
  // present-but-invalid proof fails safe to no binding (the doc stays legacy) rather than
  // blocking doc creation — the creator owns the anchor, so a captured value is genuinely theirs.
  const identity = identityUcan ? await verifyIdentityUcan(identityUcan) : null;
  if (identityUcan && !identity) {
    // A present-but-unresolved proof means either an invalid UCAN or a transient on-chain
    // read failure. Either way the doc registers UNBOUND and the binding is immutable, so the
    // gap is permanent — log it so a silent "enforces nothing forever" doc is observable.
    logger.warn({ docId }, "gate/register: identityUcan present but not captured — doc registers unbound");
  }

  const outcome = await registerGateDoc(docId, anchor, acceptedRoots, identity?.identityContractAddress);
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
