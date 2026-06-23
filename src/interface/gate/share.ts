// POST /gate/share — derive a share for the owner. The owner may pull ANY epoch
// (that's how revoke pre-wraps epoch n+1).
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { getGateMasterKey } from "../../infra/gate-keys";
import { assertOwnerAuthorized, deriveGateShare, getGateDoc } from "../../domain/gate";
import { docIdField } from "./validation";

const shareValidation = {
  body: Joi.object({
    docId: docIdField(),
    epoch: Joi.number().integer().min(0).max(Number.MAX_SAFE_INTEGER).required(),
    ownerUcan: Joi.string().required(),
  }),
};

async function shareGateShare(req: Request, res: Response): Promise<void> {
  const { docId, epoch, ownerUcan } = req.body as {
    docId: string;
    epoch: number;
    ownerUcan: string;
  };

  const masterKey = getGateMasterKey();
  if (!masterKey) return throwError({ code: 503, message: GateErrorCode.MASTER_KEY_NOT_CONFIGURED });

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  await assertOwnerAuthorized(ownerUcan, docId, doc.anchorRef);
  res.json({
    shares: {
      view: deriveGateShare(masterKey, doc.anchorRef, epoch, "view"),
      comment: deriveGateShare(masterKey, doc.anchorRef, epoch, "comment"),
    },
  });
}

// convert:false: epoch must arrive as a JSON number.
export default [validate(shareValidation, {}, { convert: false }), shareGateShare];
