// Role ordering shared by enroll (the commitment cap) and resolve-roots (the union).
// edit ⊇ comment ⊇ view — a member's effective role is the MAX over their bindings.
import type { GateDocRecord } from "../../infra/database/models";
import type { GateRole } from "./share-derivation";
import { getGateGroup } from "./group-get";

export const ROLE_RANK: Record<GateRole, number> = { view: 1, comment: 2, edit: 3 };

export const roleRank = (role: string): number =>
  ROLE_RANK[role as GateRole] ?? 0;

/** Commitments whose binding role === role (the doc's role-filtered member subset). */
export const membersForRole = (doc: GateDocRecord, role: GateRole): string[] =>
  doc.members.filter((c) =>
    doc.bindings.some((b) => b.commitment === c && b.role === role)
  );

/** The highest role held by ANY binding under this commitment, or null if none. */
export const maxRoleForCommitment = (
  doc: GateDocRecord,
  commitment: string
): GateRole | null => {
  let best: GateRole | null = null;
  for (const b of doc.bindings) {
    if (b.commitment !== commitment) continue;
    if (best === null || roleRank(b.role) > ROLE_RANK[best]) best = b.role as GateRole;
  }
  return best;
};

/** Self-enroll cap: a new binding may not exceed the commitment's current max role. */
export const capRole = (voucherRole: GateRole, maxRole: GateRole | null): GateRole =>
  maxRole === null || ROLE_RANK[voucherRole] <= ROLE_RANK[maxRole] ? voucherRole : maxRole;

/** Positive-state edit union: direct doc bindings@edit ∪ members of any edit-attached group,
 * deduped. Single source of truth — mint-time (isEditMember) and poll-time (edit-bound
 * endpoint) membership checks MUST agree, so both derive from this. */
export const editMemberCommitments = async (doc: GateDocRecord): Promise<string[]> => {
  const union = new Set(membersForRole(doc, "edit"));
  for (const { groupRef, role } of doc.acceptedRoots) {
    if (role !== "edit" || groupRef === doc.docId) continue;
    const group = await getGateGroup(groupRef);
    group?.members.forEach((c) => union.add(c));
  }
  return [...union];
};

/** Positive-state edit membership: direct doc bindings@edit ∪ members of any edit-attached group. */
export const isEditMember = async (doc: GateDocRecord, commitment: string): Promise<boolean> =>
  (await editMemberCommitments(doc)).includes(commitment);
