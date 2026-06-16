// /group/:groupRef/enroll PIN+ADD. Returns a discriminated EnrollOutcome (the
// controller maps it to a status); no throwError here. Byte-for-byte copy of
// enroll.ts's CAS loop against GateGroup/getGateGroup (the "unknown-doc" arm here
// means unknown-group; the controller 404s via getGateGroup before this runs).
import { GateGroup } from "../../infra/database/models";
import type { EnrollOutcome } from "./enroll";
import { getGateGroup } from "./group-get";

/**
 * PIN+ADD. The update filter excludes groups already binding this idHash (and already
 * holding the commitment when it must be pushed), so a concurrent duplicate enroll
 * can't double-append; the loser loops, re-reads, and resolves terminally.
 */
export const appendGroupEnrollment = async (
  groupRef: string,
  idHash: string,
  commitment: string,
  role: string
): Promise<EnrollOutcome> => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const group = await getGateGroup(groupRef);
    if (!group) return "unknown-doc";
    const bound = group.bindings.find((b) => b.idHash === idHash);
    if (bound) return bound.commitment === commitment ? "noop" : "pin-conflict";

    // Same Privy user via a second identifier reuses their commitment: append the
    // binding only, never a duplicate member. The memberAlready arm requires
    // membership so a concurrent revoke that pulled it forces a re-read.
    const memberAlready = group.members.includes(commitment);
    const filter: Record<string, unknown> = {
      groupRef,
      "bindings.idHash": { $ne: idHash },
      ...(memberAlready ? { members: commitment } : { members: { $ne: commitment } }),
    };
    const update = memberAlready
      ? { $push: { bindings: { idHash, commitment, role } } }
      : { $push: { bindings: { idHash, commitment, role }, members: commitment } };
    // runValidators: this is the sole path that writes commitments.
    const result = await GateGroup.updateOne(filter, update, { runValidators: true });
    if (result.modifiedCount === 1) return "added";
    // Raced with another enroll — next pass re-reads and terminates.
  }
  throw new Error("gate: group enrollment contention — retry");
};
