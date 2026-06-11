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
 */
export const registerGateDoc = async (
  docId: string,
  anchorRef: GateAnchorRef,
  acceptedRoots: GateAcceptedRoot[]
): Promise<RegisterOutcome> => {
  let existing = await getGateDoc(docId);
  if (!existing) {
    try {
      await GateDoc.create({ docId, anchorRef, acceptedRoots, currentEpoch: 0, members: [], bindings: [] });
      return { kind: "ok", currentEpoch: 0 };
    } catch (error) {
      // E11000 — lost a create race; fall through to the existing-doc path.
      existing = await getGateDoc(docId);
      if (!existing) throw error;
    }
  }
  if (!sameAnchor(existing.anchorRef, anchorRef)) return { kind: "anchor-mismatch" };
  const updated = await GateDoc.findOneAndUpdate(
    { docId },
    { $set: { acceptedRoots } },
    { new: true }
  ).lean<GateDocRecord | null>();
  return { kind: "ok", currentEpoch: updated ? updated.currentEpoch : existing.currentEpoch };
};
