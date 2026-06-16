// GET /gate/group/:groupRef — members in EXACT append order (clients rebuild the
// LeanIMT from this) plus the derived root. Mirrors group.ts (the per-doc reader).
import { Request, Response } from "express";
import { computeGroupRoot, getGateGroup } from "../../domain/gate";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";

async function getGroup(req: Request, res: Response): Promise<void> {
  const group = await getGateGroup(req.params.groupRef);
  if (!group) return throwError({ code: 404, message: GateErrorCode.GROUP_NOT_REGISTERED });
  res.json({ root: computeGroupRoot(group.members), members: group.members });
}

export default [getGroup];
