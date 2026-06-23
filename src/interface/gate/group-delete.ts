// POST /gate/group/:groupRef/delete — owner-asserted WHOLE-GROUP delete (hard
// revoke). Auth mirrors group-revoke (capability gate/ADMIN on the groupRef +
// LIVE on-chain PORTAL owner cross-check), but it removes the entire group row
// instead of one member. resolveAcceptedRoots then skips the group for every doc
// that attached it → access denied everywhere at the next /release. NO epoch /
// re-key (deferred). The cross-portal attach rule means every affected doc is on
// this same host portal, so the portal-owner auth covers them all.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { assertGroupOwnerAuthorized, deleteGateGroup, getGateGroup } from "../../domain/gate";

const groupDeleteValidation = {
  body: Joi.object({
    ownerUcan: Joi.string().required(),
  }),
};

async function deleteGroup(req: Request, res: Response): Promise<void> {
  const groupRef = req.params.groupRef;
  const { ownerUcan } = req.body as { ownerUcan: string };

  // A missing group 404s (the client treats it as already-deleted / idempotent).
  // Auth needs the group's anchorRef (host portal) to cross-check the owner, so it
  // must read the group first — a row that's already gone can't be re-authorized.
  const group = await getGateGroup(groupRef);
  if (!group) return throwError({ code: 404, message: GateErrorCode.GROUP_NOT_REGISTERED });

  await assertGroupOwnerAuthorized(ownerUcan, groupRef, group.anchorRef);

  await deleteGateGroup(groupRef);
  res.status(204).end();
}

// convert:false: uniform with the other gate schemas.
export default [validate(groupDeleteValidation, {}, { convert: false }), deleteGroup];
