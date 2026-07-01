// Doc↔group attach/detach: add/remove a group's root entry in the doc's acceptedRoots.
// Option A — no key, no re-wrap; attach is just routing. Returns a discriminated
// outcome (the controller maps it to a status); no throwError here.
import { GateDoc } from "../../infra/database/models";
import type { GateAcceptedRoot } from "../../infra/database/models";
import { getGateDoc } from "./get";

export type AttachOutcome = { kind: "ok" } | { kind: "unknown-doc" } | { kind: "already" } | { kind: "absent" } | { kind: "relabeled" };

export const attachGroupToDoc = async (
  docId: string,
  groupRef: string,
  role: GateAcceptedRoot["role"]
): Promise<AttachOutcome> => {
  const doc = await getGateDoc(docId);
  if (!doc) return { kind: "unknown-doc" };
  // acceptedRoots is a routing table resolve-roots reads fresh per /release, so an
  // already-attached group at a DIFFERENT role must be relabeled in place — a no-op
  // here would silently strand the role change and the member's capability never moves.
  const existing = doc.acceptedRoots.find((r) => r.groupRef === groupRef);
  if (existing) {
    if (existing.role === role) return { kind: "already" };
    await GateDoc.updateOne(
      { docId, "acceptedRoots.groupRef": groupRef },
      { $set: { "acceptedRoots.$.role": role } }
    );
    return { kind: "relabeled" };
  }
  await GateDoc.updateOne({ docId }, { $push: { acceptedRoots: { groupRef, role } } });
  return { kind: "ok" };
};

export const detachGroupFromDoc = async (docId: string, groupRef: string): Promise<AttachOutcome> => {
  const doc = await getGateDoc(docId);
  if (!doc) return { kind: "unknown-doc" };
  if (!doc.acceptedRoots.some((r) => r.groupRef === groupRef)) return { kind: "absent" };
  await GateDoc.updateOne({ docId }, { $pull: { acceptedRoots: { groupRef } } });
  return { kind: "ok" };
};
