// POST /gate/relabel-bulk — owner-asserted bulk role change (changeTier WIDEN/NARROW).
// Same collaborator auth as /relabel; commitment-scoped per idHash.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { assertCollaboratorAuthorized, getGateDoc, relabelMembersRole } from "../../domain/gate";
import { docIdField } from "./validation";

const relabelBulkValidation = {
  body: Joi.object({
    docId: docIdField(),
    idHashes: Joi.array().items(Joi.string()).min(1).required(),
    newRole: Joi.string().valid("view", "comment", "edit").required(),
    ownerUcan: Joi.string().required(),
  }),
};

async function relabelMembersBulk(req: Request, res: Response): Promise<void> {
  const { docId, idHashes, newRole, ownerUcan } = req.body as {
    docId: string;
    idHashes: string[];
    newRole: string;
    ownerUcan: string;
  };

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  await assertCollaboratorAuthorized(ownerUcan, docId, doc.anchorRef);

  const outcome = await relabelMembersRole(docId, idHashes, newRole);
  if (outcome.kind === "unknown-doc") return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  res.status(204).end();
}

export default [validate(relabelBulkValidation, {}, { convert: false }), relabelMembersBulk];
