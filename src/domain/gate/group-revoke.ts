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
    if (!binding) {
      // Never-enrolled / already-removed: record the revocation, but pin "still no
      // binding for this idHash" — if a concurrent first-enroll added one in this
      // window, the filter misses → we retry, re-read, and take the pull path below
      // (evicting them) instead of leaving them enrolled-but-denylisted.
      const denyResult = await GateGroup.updateOne(
        { groupRef, "bindings.idHash": { $ne: idHash } },
        { $addToSet: { revokedIdHashes: idHash } }
      );
      if (denyResult.matchedCount === 1) return { kind: "ok" };
      continue; // a binding appeared concurrently — re-read into the pull path
    }

    // Pin the exact snapshot binding; pull every binding sharing this commitment and
    // record the revocation atomically.
    const result = await GateGroup.updateOne(
      { groupRef, bindings: { $elemMatch: { idHash, commitment: binding.commitment } } },
      {
        $pull: { members: binding.commitment, bindings: { commitment: binding.commitment } },
        $addToSet: { revokedIdHashes: idHash },
      }
    );
    if (result.matchedCount === 1) return { kind: "ok" };
    // Missed: the binding drifted — re-read decides.
  }
  throw new Error("gate: group revoke contention — retry");
};
