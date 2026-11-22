// Reverse of a doc's acceptedRoots: every doc that edit-attaches this group. Drives the
// client's rotation fan-out on a group edit-loss (group revoke / detach / delete), so it is
// authoritative rather than device-local. See docs/architecture/gp-semaphore.md.
import { GateDoc } from "../../infra/database/models";
import type { GateAcceptedRoot, GateAnchorRef } from "../../infra/database/models/gate-doc";

export const listEditAttachedDocIds = async (groupRef: string): Promise<string[]> => {
  const docs = await GateDoc.find(
    { acceptedRoots: { $elemMatch: { groupRef, role: "edit" } } },
    { docId: 1 }
  ).lean<{ docId: string }[]>();
  return docs.map((d) => d.docId);
};

export const listGroupAttachments = async (
  groupRef: string,
  identityContract?: string
): Promise<{
  gateId: string;
  role: GateAcceptedRoot["role"];
  creatorMatches?: boolean;
  ownedAnchor?: GateAnchorRef;
}[]> => {
  const docs = await GateDoc.find(
    { docId: { $ne: groupRef }, "acceptedRoots.groupRef": groupRef },
    {
      docId: 1,
      acceptedRoots: { $elemMatch: { groupRef } },
      ...(identityContract ? { ownerIdentityContract: 1, anchorRef: 1 } : {}),
    }
  ).lean<{
    docId: string;
    acceptedRoots: GateAcceptedRoot[];
    ownerIdentityContract?: string;
    anchorRef?: GateAnchorRef;
  }[]>();
  return docs.flatMap(({ docId, acceptedRoots, ownerIdentityContract, anchorRef }) => {
    const creatorMatches = identityContract && ownerIdentityContract
      ? identityContract === ownerIdentityContract : undefined;
    return acceptedRoots.map(({ role }) => ({
      gateId: docId,
      role,
      ...(creatorMatches !== undefined ? { creatorMatches } : {}),
      ...(creatorMatches && anchorRef ? { ownedAnchor: anchorRef } : {}),
    }));
  });
};
