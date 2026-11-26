// POST /gate/group/:groupRef/attached-docs — owner-authed reverse lookup. Owner proof is a
// UCAN in the body (as with group revoke/enroll), so this is POST not GET.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { assertGroupOwnerAuthorized, getGateGroup, listEditAttachedDocIds, listGroupAttachments, verifyIdentityUcan } from "../../domain/gate";

const attachedDocsValidation = {
  body: Joi.object({
    ownerUcan: Joi.string().required(),
    scope: Joi.string().valid("all"),
    identityUcan: Joi.string().when("scope", { is: Joi.valid("all").required(), otherwise: Joi.forbidden() }),
  }),
};

async function listGroupAttachedDocs(req: Request, res: Response): Promise<void> {
  const groupRef = req.params.groupRef;
  const { ownerUcan, scope, identityUcan } = req.body as { ownerUcan: string; scope?: "all"; identityUcan?: string };

  const group = await getGateGroup(groupRef);
  if (!group) return throwError({ code: 404, message: GateErrorCode.GROUP_NOT_REGISTERED });

  await assertGroupOwnerAuthorized(ownerUcan, groupRef, group.anchorRef);

  if (scope === "all") {
    const identity = identityUcan ? await verifyIdentityUcan(identityUcan) : null;
    if (identityUcan && !identity) return throwError({ code: 403, message: GateErrorCode.NOT_DOC_OWNER });
    res.json({ attachments: await listGroupAttachments(groupRef, identity?.identityContractAddress) });
    return;
  }

  const docIds = await listEditAttachedDocIds(groupRef);
  res.json({ docIds });
}

// convert:false: uniform with the other gate schemas.
export default [validate(attachedDocsValidation, {}, { convert: false }), listGroupAttachedDocs];
