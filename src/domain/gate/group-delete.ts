// /group/:groupRef/delete — whole-group HARD delete (groups-semaphore hard-revoke).
// Removing the gate row makes resolveAcceptedRoots skip the group (its `if (!group)
// continue`) for EVERY doc that attached it — so one delete revokes the group's
// access across all attached docs at once, with no per-doc fan-out. Contrast
// group-revoke (one member) and detach (one doc). NO epoch, NO re-key here
// (deferred): a member who ALREADY opened a doc and cached the raw fileKey keeps
// reading until that doc is re-keyed — parity with member-revoke / detach today.
import { GateGroup } from "../../infra/database/models";

export type GroupDeleteOutcome = { kind: "ok" } | { kind: "unknown-group" };

export const deleteGateGroup = async (
  groupRef: string
): Promise<GroupDeleteOutcome> => {
  const result = await GateGroup.deleteOne({ groupRef });
  return result.deletedCount === 1 ? { kind: "ok" } : { kind: "unknown-group" };
};
