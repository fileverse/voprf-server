// GET /gate/doc/:docId/group — per-role member lists in EXACT append order (clients
// rebuild the LeanIMT for their own role's root from this) plus each role's derived root.
// Role filtering preserves doc.members append order (filter keeps order).
import { Request, Response } from "express";
import { computeGroupRoot, getGateDoc } from "../../domain/gate";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";

const membersForRole = (
  members: string[],
  bindings: { commitment: string; role: string }[],
  role: "view" | "comment"
): string[] =>
  members.filter((c) => bindings.some((b) => b.commitment === c && b.role === role));

async function getGroup(req: Request, res: Response): Promise<void> {
  const doc = await getGateDoc(req.params.docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  const view = membersForRole(doc.members, doc.bindings, "view");
  const comment = membersForRole(doc.members, doc.bindings, "comment");
  res.json({
    view: { root: computeGroupRoot(view), members: view },
    comment: { root: computeGroupRoot(comment), members: comment },
  });
}

export default [getGroup];
