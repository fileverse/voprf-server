// GET /gate/doc/:docId/group — members in EXACT append order (clients rebuild the
// LeanIMT from this) plus the derived root.
import { Request, Response } from "express";
import { computeGroupRoot, getGateDoc } from "../../domain/gate";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";

async function getGroup(req: Request, res: Response): Promise<void> {
  const doc = await getGateDoc(req.params.docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  res.json({ root: computeGroupRoot(doc.members), members: doc.members });
}

export default [getGroup];
