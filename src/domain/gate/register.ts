// /register upsert. Returns a discriminated RegisterOutcome (the controller maps
// it to a status); no throwError here.
import { GateDoc } from "../../infra/database/models";
import type { GateAnchorRef, GateAcceptedRoot, GateDocRecord } from "../../infra/database/models";
import { getGateDoc } from "./get";

export type RegisterOutcome =
  | { kind: "ok"; currentEpoch: number }
  | { kind: "anchor-mismatch" };

const sameAnchor = (a: GateAnchorRef, b: GateAnchorRef): boolean =>
  a.chainId === b.chainId && a.portalAddress === b.portalAddress && a.fileId === b.fileId;

/**
 * Upsert: create at epoch 0, or refresh acceptedRoots for an existing SAME-anchor
 * doc while preserving group/bindings/currentEpoch (idempotent on replay). A
 * DIFFERENT anchor is first-writer-wins → 409 (anti-squatting, D-1).
 *
 * Register owns ONLY the doc's own role roots (groupRef === docId). Attached-group
 * entries are authored exclusively by /attach and /detach and are carried over on a
 * re-register: a client re-anchor ($set of the doc-own roots) must never silently
 * detach groups — a wiped group root flips /edit-bound unbound and hard-kicks every
 * live group editor mid-session. Foreign entries in the CALLER's list are dropped
 * for the same single-writer reason.
 */
export const registerGateDoc = async (
  docId: string,
  anchorRef: GateAnchorRef,
  acceptedRoots: GateAcceptedRoot[],
  ownerIdentityContract?: string
): Promise<RegisterOutcome> => {
  const docOwnRoots = acceptedRoots.filter((r) => r.groupRef === docId);
  let existing = await getGateDoc(docId);
  if (!existing) {
    try {
      // ownerIdentityContract is written ONCE at create and never on refresh (see below), so
      // the creator's identity binding is immutable — a later re-register cannot rebind it.
      await GateDoc.create({
        docId,
        anchorRef,
        acceptedRoots: docOwnRoots,
        currentEpoch: 0,
        members: [],
        bindings: [],
        ...(ownerIdentityContract ? { ownerIdentityContract: ownerIdentityContract.toLowerCase() } : {}),
      });
      return { kind: "ok", currentEpoch: 0 };
    } catch (error) {
      // E11000 — lost a create race; fall through to the existing-doc path.
      existing = await getGateDoc(docId);
      if (!existing) throw error;
    }
  }
  if (!sameAnchor(existing.anchorRef, anchorRef)) return { kind: "anchor-mismatch" };
  const groupEntries = existing.acceptedRoots.filter((r) => r.groupRef !== docId);
  const updated = await GateDoc.findOneAndUpdate(
    { docId },
    { $set: { acceptedRoots: [...docOwnRoots, ...groupEntries] } },
    { new: true }
  ).lean<GateDocRecord | null>();
  return { kind: "ok", currentEpoch: updated ? updated.currentEpoch : existing.currentEpoch };
};
