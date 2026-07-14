// Edit-denylist — the durable half of a demote-off-edit. A demoted member keeps a
// cryptographically-valid EDIT voucher and, in a live session, re-enrolls with it on
// the next reconnect (reader re-enroll), relabeling their gate binding back to edit and
// undoing the demote. Recording the idHash here lets /enroll refuse an 'edit' enroll for
// them until an owner promote-to-edit lifts it. Pure $addToSet / $pull; idempotent.
import { GateDoc } from "../../infra/database/models";

export const addEditDenied = async (docId: string, idHash: string): Promise<void> => {
  await GateDoc.updateOne({ docId }, { $addToSet: { editDeniedIdHashes: idHash } });
};

export const removeEditDenied = async (docId: string, idHash: string): Promise<void> => {
  await GateDoc.updateOne({ docId }, { $pull: { editDeniedIdHashes: idHash } });
};
