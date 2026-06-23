// /revoke: forward-only epoch advance + member removal. Returns a discriminated
// RevokeOutcome (the controller maps it to a status); no throwError here.
import { GateDoc } from "../../infra/database/models";
import { getGateDoc } from "./get";

export type RevokeOutcome =
  | { kind: "ok" }
  | { kind: "stale-epoch"; currentEpoch: number }
  | { kind: "unknown-doc" };

/**
 * Forward-only epoch advance + best-effort member removal + denylist write in one
 * atomic update. A never-enrolled idHash still advances the epoch (the blob is already
 * re-wrapped at targetEpoch — refusing would lock everyone out) and is denylisted so it
 * can't re-enroll later. Bounded CAS retries; the $elemMatch / no-binding $ne pins stop
 * a concurrent enroll or commitment swap from slipping a member past the eviction.
 * addToDenylist=false is the mechanical epoch-bump (changeTier ghost-revoke): no denylist.
 */
export const revokeGateMember = async (
  docId: string,
  idHash: string,
  targetEpoch: number,
  addToDenylist: boolean = true
): Promise<RevokeOutcome> => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const doc = await getGateDoc(docId);
    if (!doc) return { kind: "unknown-doc" };
    if (targetEpoch < doc.currentEpoch) return { kind: "stale-epoch", currentEpoch: doc.currentEpoch };

    const binding = doc.bindings.find((b) => b.idHash === idHash);
    const filter: Record<string, unknown> = { docId, currentEpoch: { $lte: targetEpoch } };
    const update: Record<string, unknown> = { $set: { currentEpoch: targetEpoch } };
    if (binding) {
      // Pin the exact snapshot binding: a concurrent commitment swap misses → re-read.
      filter.bindings = { $elemMatch: { idHash, commitment: binding.commitment } };
      // Pull every binding sharing this commitment, not just this idHash: a sibling
      // identifier's dangling binding would otherwise block future re-enroll.
      update.$pull = { members: binding.commitment, bindings: { commitment: binding.commitment } };
    } else {
      // No binding at read time. Pin that: if a concurrent first-enroll added a binding
      // for this idHash between the read and this write, the filter misses → matchedCount
      // 0 → we retry, re-read, find the binding, and take the pull path (evicting them).
      // Without this pin the revoke would "succeed" (epoch bump only) and leave the
      // just-enrolled member in the tree but denylisted — never evicted.
      filter["bindings.idHash"] = { $ne: idHash };
    }
    // Record the revocation so /enroll refuses re-entry (the sole revocation backstop).
    // Covers the never-enrolled-then-removed case: a binding may be absent, but the
    // epoch $set still runs, so the $addToSet lands on the same atomic update.
    // addToDenylist=false is the mechanical epoch-bump (changeTier ghost-revoke).
    if (addToDenylist) {
      update.$addToSet = { revokedIdHashes: idHash };
    }
    const result = await GateDoc.updateOne(filter, update);
    if (result.matchedCount === 1) return { kind: "ok" };
    // Missed: epoch advanced past target, or the binding drifted — re-read decides.
  }
  throw new Error("gate: revoke contention — retry");
};
