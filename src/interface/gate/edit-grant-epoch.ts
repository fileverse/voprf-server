// GET /gate/doc/:docId/edit-grant-epoch — public read of the edit-admission epoch. The
// collaboration-server reads this (lazy, cached) to advance its pinned epoch and drop stale
// editor sockets on an owner-triggered refresh. Non-secret (a bare monotonic counter); no auth.
import { Request, Response } from "express";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { getEditGrantEpoch } from "../../domain/gate";

async function readEditGrantEpoch(req: Request, res: Response): Promise<void> {
  const { docId } = req.params as { docId: string };
  const editGrantEpoch = await getEditGrantEpoch(docId);
  if (editGrantEpoch === null) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  res.json({ editGrantEpoch });
}

export default [readEditGrantEpoch];
