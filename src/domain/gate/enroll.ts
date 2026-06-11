// /enroll PIN+ADD. Returns a discriminated EnrollOutcome (the controller maps it
// to a status); no throwError here.
import { GateDoc } from "../../infra/database/models";
import { getGateDoc } from "./get";

export type EnrollOutcome = "added" | "noop" | "pin-conflict" | "unknown-doc";

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
    const bound = doc.bindings.find((b) => b.idHash === idHash);
    if (bound) return bound.commitment === commitment ? "noop" : "pin-conflict";

    // Same Privy user via a second identifier reuses their commitment: append the
    // binding only, never a duplicate member. The memberAlready arm requires
    // membership so a concurrent revoke that pulled it forces a re-read.
    const memberAlready = doc.members.includes(commitment);
    const filter: Record<string, unknown> = {
      docId,
      "bindings.idHash": { $ne: idHash },
      ...(memberAlready ? { members: commitment } : { members: { $ne: commitment } }),
    };
    const update = memberAlready
      ? { $push: { bindings: { idHash, commitment, role } } }
      : { $push: { bindings: { idHash, commitment, role }, members: commitment } };
    // runValidators: this is the sole path that writes commitments.
    const result = await GateDoc.updateOne(filter, update, { runValidators: true });
    if (result.modifiedCount === 1) return "added";
    // Raced with another enroll — next pass re-reads and terminates.
  }
  throw new Error("gate: enrollment contention — retry");
};
