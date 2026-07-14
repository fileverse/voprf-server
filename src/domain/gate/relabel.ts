// /relabel — owner-initiated single-member role change (comment ⇄ view ⇄ edit). Resolves
// the idHash to its commitment and relabels EVERY binding under that commitment: /release
// proves per-commitment (resolve-roots membersForRole filters doc.members by commitment),
// so a lone binding left at the old role keeps the member in that role-filtered set.
// Same commitment-scoping the revoke $pull uses. No currentEpoch bump — a relabel is not
// a re-key. wasEdit lets the controller decide whether this demote must bump editGrantEpoch.
import { GateDoc } from "../../infra/database/models";
import { getGateDoc } from "./get";

export type RelabelOutcome = { kind: "ok"; wasEdit: boolean } | { kind: "unknown-doc" };

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
  return { kind: "ok", wasEdit };
};
