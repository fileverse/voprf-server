// POST /gate/reinstate — owner-asserted lift of an idHash revocation.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { assertOwnerAuthorized, getGateDoc, reinstateGateMember } from "../../domain/gate";
import { docIdField } from "./validation";

const reinstateValidation = {
  body: Joi.object({
    docId: docIdField(),
    idHash: Joi.string().required(),
    ownerUcan: Joi.string().required(),
  }),
};

async function reinstateMember(req: Request, res: Response): Promise<void> {
  const { docId, idHash, ownerUcan } = req.body as {
    docId: string;
    idHash: string;
    ownerUcan: string;
  };

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  await assertOwnerAuthorized(ownerUcan, docId, doc.anchorRef);

  const outcome = await reinstateGateMember(docId, idHash);
  if (outcome.kind === "unknown-doc") return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  res.status(204).end();
}

export default [validate(reinstateValidation, {}, { convert: false }), reinstateMember];
