// POST /gate/doc/:docId/edit-bound — per-actor batch admission check. The collab-server
// polls this with opaque per-doc edit handles; response reveals only which handles are
// currently edit-bound (the handle is unforgeable, gate-internal), so no auth. Uses
// editMemberCommitments — the same union isEditMember checks at mint time — so a minted
// editUcan can never be reported unbound here.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { deriveEditHandle, editMemberCommitments, getGateDoc } from "../../domain/gate";
import { docIdField } from "./validation";

// Bounds poll cost to a sane collab-room roster size.
const MAX_HANDLES = 512;

const editBoundValidation = {
  params: Joi.object({
    docId: docIdField(),
  }),
  body: Joi.object({
    handles: Joi.array().items(Joi.string()).max(MAX_HANDLES).required(),
  }),
};

async function editBound(req: Request, res: Response): Promise<void> {
  const { docId } = req.params as { docId: string };
  const { handles } = req.body as { handles: string[] };

  const doc = await getGateDoc(docId);
  if (!doc) {
    res.json({ bound: [] });
    return;
  }

  const union = await editMemberCommitments(doc);
  const boundSet = new Set(union.map((c) => deriveEditHandle(c, docId)));
  res.json({ bound: handles.filter((h) => boundSet.has(h)) });
}

export default [validate(editBoundValidation, {}, { convert: false }), editBound];
