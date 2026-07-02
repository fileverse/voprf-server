// POST /gate/relabel — owner-asserted single-member role change (comment ⇄ view).
// A doc-op: same collaborator auth as revoke/reinstate. No epoch, no denylist.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { assertCollaboratorAuthorized, getGateDoc, relabelMemberRole } from "../../domain/gate";
import { docIdField } from "./validation";

const relabelValidation = {
  body: Joi.object({
    docId: docIdField(),
    idHash: Joi.string().required(),
    newRole: Joi.string().valid("view", "comment").required(),
    ownerUcan: Joi.string().required(),
  }),
};

async function relabelMember(req: Request, res: Response): Promise<void> {
  const { docId, idHash, newRole, ownerUcan } = req.body as {
    docId: string;
    idHash: string;
    newRole: string;
    ownerUcan: string;
  };

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  await assertCollaboratorAuthorized(ownerUcan, docId, doc.anchorRef);

  const outcome = await relabelMemberRole(docId, idHash, newRole);
  if (outcome.kind === "unknown-doc") return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  res.status(204).end();
}

export default [validate(relabelValidation, {}, { convert: false }), relabelMember];
