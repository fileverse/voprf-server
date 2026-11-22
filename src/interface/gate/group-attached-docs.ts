// POST /gate/group/:groupRef/attached-docs — owner-authed reverse lookup. Owner proof is a
// UCAN in the body (as with group revoke/enroll), so this is POST not GET.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { assertGroupOwnerAuthorized, getGateGroup, listEditAttachedDocIds, listGroupAttachments } from "../../domain/gate";

const attachedDocsValidation = {
  body: Joi.object({
    ownerUcan: Joi.string().required(),
    scope: Joi.string().valid("all"),
  }),
};

async function listGroupAttachedDocs(req: Request, res: Response): Promise<void> {
  const groupRef = req.params.groupRef;
  const { ownerUcan, scope } = req.body as { ownerUcan: string; scope?: "all" };

  const group = await getGateGroup(groupRef);
  if (!group) return throwError({ code: 404, message: GateErrorCode.GROUP_NOT_REGISTERED });

  await assertGroupOwnerAuthorized(ownerUcan, groupRef, group.anchorRef);

  if (scope === "all") {
    res.json({ attachments: await listGroupAttachments(groupRef) });
    return;
  }

  const docIds = await listEditAttachedDocIds(groupRef);
  res.json({ docIds });
}

// convert:false: uniform with the other gate schemas.
export default [validate(attachedDocsValidation, {}, { convert: false }), listGroupAttachedDocs];
