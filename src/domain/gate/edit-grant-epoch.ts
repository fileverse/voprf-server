// editGrantEpoch — the edit-admission kill-switch, bumped on any op that removes an editor's
// right to write. Distinct from currentEpoch (fileKey re-key): a demote keeps read, so it
// must NOT re-key. $inc initializes an absent field to 1 (old docs), so it is monotonic
// even before a backfill.
import { GateDoc } from "../../infra/database/models";

/** Advance one doc's editGrantEpoch (individual demote/revoke). */
export const bumpEditGrantEpoch = async (docId: string): Promise<void> => {
  await GateDoc.updateOne({ docId }, { $inc: { editGrantEpoch: 1 } });
};

/** Fan-out: advance editGrantEpoch on every doc that accepts this group at the edit role
 *  (group-delete / group-revoke / detach-from-edit). Bounded — a group is attached to few docs. */
export const bumpEditGrantEpochForGroupAtEdit = async (groupRef: string): Promise<void> => {
  await GateDoc.updateMany(
    { acceptedRoots: { $elemMatch: { groupRef, role: "edit" } } },
    { $inc: { editGrantEpoch: 1 } }
  );
};

/** Read the current editGrantEpoch (the collab-server's re-check source). Missing field ⇒ 0. */
export const getEditGrantEpoch = async (docId: string): Promise<number | null> => {
  const doc = await GateDoc.findOne({ docId }, { editGrantEpoch: 1 }).lean();
  if (!doc) return null;
  return (doc as { editGrantEpoch?: number }).editGrantEpoch ?? 0;
};
