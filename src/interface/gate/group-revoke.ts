// POST /gate/group/:groupRef/revoke — owner-asserted membership eviction. NO epoch
// (groups-semaphore §3): pulling the commitment changes the root → stale proofs 409.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import {
  assertGroupOwnerAuthorized,
  bumpEditGrantEpochForGroupAtEdit,
  getGateGroup,
  revokeGateGroupMember,
} from "../../domain/gate";

const groupRevokeValidation = {
  body: Joi.object({
    idHash: Joi.string().required(),
    ownerUcan: Joi.string().required(),
  }),
};

async function revokeGroupMember(req: Request, res: Response): Promise<void> {
  const groupRef = req.params.groupRef;
  const { idHash, ownerUcan } = req.body as {
    idHash: string;
    ownerUcan: string;
  };

  const group = await getGateGroup(groupRef);
  if (!group) return throwError({ code: 404, message: GateErrorCode.GROUP_NOT_REGISTERED });

  await assertGroupOwnerAuthorized(ownerUcan, groupRef, group.anchorRef);

  const outcome = await revokeGateGroupMember(groupRef, idHash);
  if (outcome.kind === "unknown-group") return throwError({ code: 404, message: GateErrorCode.GROUP_NOT_REGISTERED });
  // A removed group member loses edit on every doc that accepts this group at edit.
  await bumpEditGrantEpochForGroupAtEdit(groupRef);
  res.status(204).end();
}

// convert:false: uniform with the other gate schemas.
export default [validate(groupRevokeValidation, {}, { convert: false }), revokeGroupMember];
