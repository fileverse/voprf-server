// GET /gate/doc/:docId/group — per-role member lists in EXACT append order (clients
// rebuild the LeanIMT for their own role's root from this) plus each role's derived root.
// Role filtering preserves doc.members append order (filter keeps order).
//
// currentEpoch is the epoch /release derives shares at. Clients compare it with the
// on-chain blob's epoch: a blob behind the gate means every invitee's unwrap fails,
// and the owner can re-anchor. Additive field — readers address roles by name.
import { Request, Response } from "express";
import { computeGroupRoot, getGateDoc } from "../../domain/gate";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import type { GateDocRecord } from "../../infra/database/models";

const membersForRole = (
  members: string[],
  bindings: { commitment: string; role: string }[],
  role: "view" | "comment" | "edit"
): string[] =>
  members.filter((c) => bindings.some((b) => b.commitment === c && b.role === role));

export const buildDocGroupResponse = (doc: Pick<GateDocRecord, "currentEpoch" | "members" | "bindings">) => {
  const view = membersForRole(doc.members, doc.bindings, "view");
  const comment = membersForRole(doc.members, doc.bindings, "comment");
  const edit = membersForRole(doc.members, doc.bindings, "edit");
  return {
    view: { root: computeGroupRoot(view), members: view },
    comment: { root: computeGroupRoot(comment), members: comment },
    edit: { root: computeGroupRoot(edit), members: edit },
    currentEpoch: doc.currentEpoch,
  };
};

async function getGroup(req: Request, res: Response): Promise<void> {
  const doc = await getGateDoc(req.params.docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  res.json(buildDocGroupResponse(doc));
}

export default [getGroup];
