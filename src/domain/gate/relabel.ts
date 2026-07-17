// /relabel — owner-initiated single-member role change (comment ⇄ view ⇄ edit). Resolves
// the idHash to its commitment and relabels EVERY binding under that commitment: /release
// proves per-commitment (resolve-roots membersForRole filters doc.members by commitment),
// so a lone binding left at the old role keeps the member in that role-filtered set.
// Same commitment-scoping the revoke $pull uses. No currentEpoch bump — a relabel is not
// a re-key. wasEdit tells the controller whether this was a demote off edit.
import { GateDoc } from "../../infra/database/models";
import { getGateDoc } from "./get";

export type RelabelOutcome =
  | { kind: "ok"; wasEdit: boolean; commitment?: string }
  | { kind: "unknown-doc" };

export const relabelMemberRole = async (
  docId: string,
  idHash: string,
  newRole: string
): Promise<RelabelOutcome> => {
  const doc = await getGateDoc(docId);
  if (!doc) return { kind: "unknown-doc" };

  const binding = doc.bindings.find((b) => b.idHash === idHash);
  // Not enrolled: nothing live to relabel. The client re-voucher already forces their
  // future enroll to the new role — idempotent no-op, not an error.
  if (!binding) return { kind: "ok", wasEdit: false };

  const wasEdit = binding.role === "edit";
  await GateDoc.updateOne(
    { docId },
    { $set: { "bindings.$[elem].role": newRole } },
    { arrayFilters: [{ "elem.commitment": binding.commitment }] }
  );
  return { kind: "ok", wasEdit, commitment: binding.commitment };
};

export type RelabelBulkOutcome = { kind: "ok" } | { kind: "unknown-doc" };

/** Owner bulk relabel (changeTier WIDEN/NARROW): relabel every binding under the
 *  commitment of each given idHash to newRole. Commitment-scoped, same as the single
 *  relabel — a member with multiple identifiers moves entirely. */
export const relabelMembersRole = async (
  docId: string,
  idHashes: string[],
  newRole: string
): Promise<RelabelBulkOutcome> => {
  const doc = await getGateDoc(docId);
  if (!doc) return { kind: "unknown-doc" };

  const commitments = new Set<string>();
  for (const idHash of idHashes) {
    const binding = doc.bindings.find((b) => b.idHash === idHash);
    if (binding) commitments.add(binding.commitment);
  }
  if (commitments.size === 0) return { kind: "ok" };

  await GateDoc.updateOne(
    { docId },
    { $set: { "bindings.$[elem].role": newRole } },
    { arrayFilters: [{ "elem.commitment": { $in: [...commitments] } }] }
  );
  return { kind: "ok" };
};
