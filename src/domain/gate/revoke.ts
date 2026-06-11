// /revoke: forward-only epoch advance + member removal. Returns a discriminated
// RevokeOutcome (the controller maps it to a status); no throwError here.
import { GateDoc } from "../../infra/database/models";
import { getGateDoc } from "./get";

export type RevokeOutcome =
  | { kind: "ok" }
  | { kind: "stale-epoch"; currentEpoch: number }
  | { kind: "unknown-doc" };

/**
 * Forward-only epoch advance + best-effort member removal in one atomic update. A
 * never-enrolled idHash still advances the epoch (the blob is already re-wrapped at
 * targetEpoch — refusing would lock everyone out). Bounded CAS retries; the
 * $elemMatch pin stops a concurrent revoke+re-enroll from pulling the wrong commitment.
 */
export const revokeGateMember = async (
  docId: string,
  idHash: string,
  targetEpoch: number
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
      // identifier's dangling binding would otherwise block future re-enroll. Re-entry
      // stays possible via any valid voucher (the blob is the authorization truth).
      update.$pull = { members: binding.commitment, bindings: { commitment: binding.commitment } };
    }
    const result = await GateDoc.updateOne(filter, update);
    if (result.matchedCount === 1) return { kind: "ok" };
    // Missed: epoch advanced past target, or the binding drifted — re-read decides.
  }
  throw new Error("gate: revoke contention — retry");
};
