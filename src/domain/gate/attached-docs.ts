// Reverse of a doc's acceptedRoots: every doc that edit-attaches this group. Drives the
// client's rotation fan-out on a group edit-loss (group revoke / detach / delete), so it is
// authoritative rather than device-local. See docs/architecture/gp-semaphore.md.
import { GateDoc } from "../../infra/database/models";
import type { GateAcceptedRoot } from "../../infra/database/models/gate-doc";

export const listEditAttachedDocIds = async (groupRef: string): Promise<string[]> => {
  const docs = await GateDoc.find(
    { acceptedRoots: { $elemMatch: { groupRef, role: "edit" } } },
    { docId: 1 }
  ).lean<{ docId: string }[]>();
  return docs.map((d) => d.docId);
};

export const listGroupAttachments = async (
  groupRef: string
): Promise<{ gateId: string; role: GateAcceptedRoot["role"] }[]> => {
  const docs = await GateDoc.find(
    { docId: { $ne: groupRef }, "acceptedRoots.groupRef": groupRef },
    { docId: 1, acceptedRoots: { $elemMatch: { groupRef } } }
  ).lean<{ docId: string; acceptedRoots: GateAcceptedRoot[] }[]>();
  return docs.flatMap(({ docId, acceptedRoots }) =>
    acceptedRoots.map(({ role }) => ({ gateId: docId, role }))
  );
};
