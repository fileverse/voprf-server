// /enroll PIN+ADD. Returns a discriminated EnrollOutcome (the controller maps it
// to a status); no throwError here.
import { GateDoc } from "../../infra/database/models";
import { getGateDoc } from "./get";
import { capRole, maxRoleForCommitment } from "./roles";
import type { GateRole } from "./share-derivation";

export type EnrollOutcome =
  | "added"
  | "noop"
  | "pin-conflict"
  | "unknown-doc"
  | "revoked";

/**
 * PIN+ADD. The update filter excludes docs already binding this idHash (and already
 * holding the commitment when it must be pushed), so a concurrent duplicate enroll
 * can't double-append; the loser loops, re-reads, and resolves terminally.
 */
export const appendEnrollment = async (
  docId: string,
  idHash: string,
  commitment: string,
  role: string
): Promise<EnrollOutcome> => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const doc = await getGateDoc(docId);
    if (!doc) return "unknown-doc";
    if ((doc.revokedIdHashes ?? []).includes(idHash)) return "revoked";

    // Self-enroll NEVER raises a role. An existing binding is a pure noop
    // (or pin-conflict); role changes are owner-authenticated (/relabel) only.
    const bound = doc.bindings.find((b) => b.idHash === idHash);
    if (bound) {
      return bound.commitment === commitment ? "noop" : "pin-conflict";
    }

    // New idHash. A second idHash for an already-enrolled commitment is capped at
    // that commitment's current max role, so a demoted member's stale higher-role
    // voucher on a fresh identifier cannot re-raise the commitment (gp-semaphore §demote).
    const memberAlready = doc.members.includes(commitment);
    const effectiveRole = memberAlready
      ? capRole(role as GateRole, maxRoleForCommitment(doc, commitment))
      : role;

    const filter: Record<string, unknown> = {
      docId,
      "bindings.idHash": { $ne: idHash },
      revokedIdHashes: { $ne: idHash },
      ...(memberAlready ? { members: commitment } : { members: { $ne: commitment } }),
    };
    const update = memberAlready
      ? { $push: { bindings: { idHash, commitment, role: effectiveRole } } }
      : { $push: { bindings: { idHash, commitment, role: effectiveRole }, members: commitment } };
    const result = await GateDoc.updateOne(filter, update, { runValidators: true });
    if (result.modifiedCount === 1) return "added";
  }
  throw new Error("gate: enrollment contention — retry");
};
