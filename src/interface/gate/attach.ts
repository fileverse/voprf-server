
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import {
  assertCollaboratorAuthorized,
  attachGroupToDoc,
  detachGroupFromDoc,
  getGateDoc,
  getGateGroup,
} from "../../domain/gate";
import type { GateAcceptedRoot } from "../../infra/database/models";
import { groupRefField } from "./validation";

const attachValidation = {
  body: Joi.object({
    groupRef: groupRefField(),
    role: Joi.string().valid("view", "comment").required(),
    ownerUcan: Joi.string().required(),
  }),
};

async function attachGroup(req: Request, res: Response): Promise<void> {
  const docId = req.params.docId;
  const { groupRef, role, ownerUcan } = req.body as {
    groupRef: string;
    role: GateAcceptedRoot["role"];
    ownerUcan: string;
  };

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  // Any portal collaborator authorizes the attach (the doc's acceptedRoots is
  // what changes); the owner is a collaborator too.
  await assertCollaboratorAuthorized(ownerUcan, docId, doc.anchorRef);

  const group = await getGateGroup(groupRef);
  if (!group) return throwError({ code: 404, message: GateErrorCode.GROUP_NOT_REGISTERED });

  // Cross-portal rule: a group may only be attached to a doc on the SAME host portal
  // (both anchors lowercased at register). Otherwise the doc owner could route a
  // foreign portal's group root onto their doc.
  if (group.anchorRef.portalAddress !== doc.anchorRef.portalAddress) {
    return throwError({ code: 403, message: GateErrorCode.CROSS_PORTAL_ATTACH });
  }

  const outcome = await attachGroupToDoc(docId, groupRef, role);
  if (outcome.kind === "unknown-doc") return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  res.status(204).end();
}

const detachValidation = {
  body: Joi.object({
    groupRef: groupRefField(),
    ownerUcan: Joi.string().required(),
  }),
};

async function detachGroup(req: Request, res: Response): Promise<void> {
  const docId = req.params.docId;
  const { groupRef, ownerUcan } = req.body as {
    groupRef: string;
    ownerUcan: string;
  };

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  await assertCollaboratorAuthorized(ownerUcan, docId, doc.anchorRef);

  const outcome = await detachGroupFromDoc(docId, groupRef);
  if (outcome.kind === "unknown-doc") return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  res.status(204).end();
}

// convert:false: uniform with the other gate schemas. docId arrives as a path param
// (the doc lookup key); the body carries the group routing payload.
export const attach = [validate(attachValidation, {}, { convert: false }), attachGroup];
export const detach = [validate(detachValidation, {}, { convert: false }), detachGroup];
