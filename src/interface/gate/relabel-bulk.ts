// POST /gate/relabel-bulk — owner-asserted bulk role change (changeTier WIDEN/NARROW).
// Same collaborator auth as /relabel; commitment-scoped per idHash.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { assertCollaboratorAuthorized, assertDocOwnerIdentity, getGateDoc, relabelMembersRole } from "../../domain/gate";
import { docIdField } from "./validation";

export const relabelBulkValidation = {
  body: Joi.object({
    docId: docIdField(),
    idHashes: Joi.array().items(Joi.string()).min(1).required(),
    // Bulk relabel emits no eviction handles / epoch bump, so it must never
    // grant edit (that would be an un-rotated promote).
    newRole: Joi.string().valid("view", "comment").required(),
    ownerUcan: Joi.string().required(),
    identityUcan: Joi.string(),
  }),
};

async function relabelMembersBulk(req: Request, res: Response): Promise<void> {
  const { docId, idHashes, newRole, ownerUcan, identityUcan } = req.body as {
    docId: string;
    idHashes: string[];
    newRole: string;
    ownerUcan: string;
    identityUcan?: string;
  };

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  await assertCollaboratorAuthorized(ownerUcan, docId, doc.anchorRef);
  await assertDocOwnerIdentity(identityUcan, doc);

  const outcome = await relabelMembersRole(docId, idHashes, newRole);
  if (outcome.kind === "unknown-doc") return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  // changeTier never demotes off edit (Change #1) — no eviction, but a uniform response shape.
  res.json({ evictedHandles: [] });
}

export default [validate(relabelBulkValidation, {}, { convert: false }), relabelMembersBulk];
