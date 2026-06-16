// Additive implicit group (groups-semaphore §3 decision #2): the union of roots a
// doc's /release will accept. Each acceptedRoots entry resolves to a Semaphore root:
//   groupRef === docId → the doc's OWN inline members (the individuals path)
//   groupRef === <groupId> → gate_groups[groupId].members
// /release accepts a proof whose root is in this union. Empty/missing groups
// contribute the "0" root, which is filtered out (an empty group can't be proven).
import { computeGroupRoot } from "./group";
import { getGateGroup } from "./group-get";
import type { GateDocRecord } from "../../infra/database/models";

export const resolveAcceptedRoots = async (doc: GateDocRecord): Promise<string[]> => {
  const roots: string[] = [];
  for (const { groupRef } of doc.acceptedRoots) {
    if (groupRef === doc.docId) {
      roots.push(computeGroupRoot(doc.members));
    } else {
      const group = await getGateGroup(groupRef);
      if (group) roots.push(computeGroupRoot(group.members));
    }
  }
  // Unique, non-"0": an empty membership set yields "0", which can never be the root
  // of a valid proof — drop it so it can't accidentally match a malformed proof.
  return [...new Set(roots.filter((root) => root !== "0"))];
};
