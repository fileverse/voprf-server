// POST /gate/revoke — owner-asserted forward-only epoch advance + member removal.
// epoch ≥ 1 (400, via Joi) is checked before the stale-epoch (409) test.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import {
  assertCollaboratorAuthorized,
  bumpEditGrantEpoch,
  deriveEditHandle,
  getGateDoc,
  revokeGateMember,
} from "../../domain/gate";
import { docIdField } from "./validation";

const revokeValidation = {
  body: Joi.object({
    docId: docIdField(),
    idHash: Joi.string().required(),
    ownerUcan: Joi.string().required(),
    epoch: Joi.number().integer().min(1).max(Number.MAX_SAFE_INTEGER).required(),
    addToDenylist: Joi.boolean().optional(),
  }),
};

async function revokeMember(req: Request, res: Response): Promise<void> {
  const { docId, idHash, ownerUcan, epoch, addToDenylist } = req.body as {
    docId: string;
    idHash: string;
    ownerUcan: string;
    epoch: number;
    addToDenylist?: boolean;
  };

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  await assertCollaboratorAuthorized(ownerUcan, docId, doc.anchorRef);

  const outcome = await revokeGateMember(docId, idHash, epoch, addToDenylist ?? true);
  if (outcome.kind === "unknown-doc") return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  if (outcome.kind === "stale-epoch") {
    return throwError({
      code: 409,
      message: GateErrorCode.STALE_EPOCH,
    });
  }
  // Revoke already advances currentEpoch above; this is the independent edit-admission
  // bump, applied only when the removed member was an editor (no churn on view/comment).
  if (outcome.kind === "ok" && outcome.wasEdit) await bumpEditGrantEpoch(docId);
  const evictedHandles =
    outcome.kind === "ok" && outcome.wasEdit && outcome.commitment ? [deriveEditHandle(outcome.commitment, docId)] : [];
  res.json({ evictedHandles });
}

// convert:false: epoch must arrive as a JSON number.
export default [validate(revokeValidation, {}, { convert: false }), revokeMember];
