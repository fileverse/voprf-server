// /group/:groupRef/revoke — membership eviction (NO epoch; groups-semaphore §3).
// Pulling the member's commitment changes the group's computed root → their stale
// proof 409s and they can't build a fresh one. Returns a discriminated outcome (the
// controller maps it to a status); no throwError here. Mirrors revoke.ts's
// person-revoke arm minus all epoch logic.
import { GateGroup } from "../../infra/database/models";
import { getGateGroup } from "./group-get";

export type GroupRevokeOutcome = { kind: "ok" } | { kind: "unknown-group" };

/**
 * Best-effort member removal. A never-enrolled idHash is a no-op success (the binding
 * may already be gone). Bounded CAS retries; the $elemMatch pin stops a concurrent
 * revoke+re-enroll from pulling the wrong commitment.
 */
export const revokeGateGroupMember = async (
  groupRef: string,
  idHash: string
): Promise<GroupRevokeOutcome> => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const group = await getGateGroup(groupRef);
    if (!group) return { kind: "unknown-group" };

    const binding = group.bindings.find((b) => b.idHash === idHash);
    if (!binding) return { kind: "ok" }; // never-enrolled / already-removed — terminal no-op.

    // Pin the exact snapshot binding: a concurrent commitment swap misses → re-read.
    // Pull every binding sharing this commitment, not just this idHash: a sibling
    // identifier's dangling binding would otherwise block future re-enroll. Re-entry
    // stays possible via any valid voucher (the blob is the authorization truth).
    const result = await GateGroup.updateOne(
      { groupRef, bindings: { $elemMatch: { idHash, commitment: binding.commitment } } },
      { $pull: { members: binding.commitment, bindings: { commitment: binding.commitment } } }
    );
    if (result.matchedCount === 1) return { kind: "ok" };
    // Missed: the binding drifted — re-read decides.
  }
  throw new Error("gate: group revoke contention — retry");
};
