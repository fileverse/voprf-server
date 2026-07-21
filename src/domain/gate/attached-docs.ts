// Reverse of a doc's acceptedRoots: every doc that edit-attaches this group. Drives the
// client's rotation fan-out on a group edit-loss (group revoke / detach / delete), so it is
// authoritative rather than device-local. See docs/architecture/gp-semaphore.md.
import { GateDoc } from "../../infra/database/models";

export const listEditAttachedDocIds = async (groupRef: string): Promise<string[]> => {
  const docs = await GateDoc.find(
    { acceptedRoots: { $elemMatch: { groupRef, role: "edit" } } },
    { docId: 1 }
  ).lean<{ docId: string }[]>();
  return docs.map((d) => d.docId);
};
