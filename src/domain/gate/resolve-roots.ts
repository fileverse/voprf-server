// Additive implicit group (groups-semaphore §3 decision #2): the union of roots a
// doc's /release will accept. Each acceptedRoots entry resolves to a Semaphore root:
//   groupRef === docId → the doc's OWN inline members (the individuals path)
//   groupRef === <groupId> → gate_groups[groupId].members
// /release accepts a proof whose root is in this union. Empty/missing groups
// contribute the "0" root, which is filtered out (an empty group can't be proven).
import { computeGroupRoot } from "./group";
import { getGateGroup } from "./group-get";
import type { GateDocRecord } from "../../infra/database/models";
import type { GateRole } from "./share-derivation";

export interface AcceptedRootEntry {
  root: string;
  role: GateRole;
}

/** Commitments whose binding role === role (the doc's role-filtered member subset). */
const membersForRole = (doc: GateDocRecord, role: GateRole): string[] =>
  doc.members.filter((c) =>
    doc.bindings.some((b) => b.commitment === c && b.role === role)
  );

export const resolveAcceptedRoots = async (
  doc: GateDocRecord
): Promise<AcceptedRootEntry[]> => {
  const entries: AcceptedRootEntry[] = [];
  for (const { groupRef, role } of doc.acceptedRoots) {
    let root: string;
    if (groupRef === doc.docId) {
      root = computeGroupRoot(membersForRole(doc, role));
    } else {
      const group = await getGateGroup(groupRef);
      if (!group) continue;
      root = computeGroupRoot(group.members);
    }
    if (root !== "0") entries.push({ root, role });
  }
  // Dedupe by root. If two entries share a root (degenerate: identical member sets),
  // keep the HIGHER role (comment ⊇ view) so a match is never under-privileged.
  const byRoot = new Map<string, GateRole>();
  for (const { root, role } of entries) {
    const prev = byRoot.get(root);
    if (!prev || (prev === "view" && role === "comment")) byRoot.set(root, role);
  }
  return [...byRoot.entries()].map(([root, role]) => ({ root, role }));
};
