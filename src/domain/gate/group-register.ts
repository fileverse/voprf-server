// /group/register upsert. Returns a discriminated outcome (the controller maps it to
// a status); no throwError here. Mirrors register.ts minus acceptedRoots/currentEpoch
// (a group has NO epoch — groups-semaphore §3).
import { GateGroup } from "../../infra/database/models";
import type { GateAnchorRef } from "../../infra/database/models";
import { getGateGroup } from "./group-get";

export type GroupRegisterOutcome = { kind: "ok" } | { kind: "anchor-mismatch" };

const sameAnchor = (a: GateAnchorRef, b: GateAnchorRef): boolean =>
  a.chainId === b.chainId && a.portalAddress === b.portalAddress && a.fileId === b.fileId;

/**
 * Upsert: create an empty group, or no-op for an existing SAME-anchor group
 * (idempotent on replay). A DIFFERENT anchor is first-writer-wins → anchor-mismatch
 * (anti-squatting, mirrors registerGateDoc's D-1 pin).
 */
export const registerGateGroup = async (
  groupRef: string,
  anchorRef: GateAnchorRef
): Promise<GroupRegisterOutcome> => {
  let existing = await getGateGroup(groupRef);
  if (!existing) {
    try {
      await GateGroup.create({ groupRef, anchorRef, members: [], bindings: [] });
      return { kind: "ok" };
    } catch (error) {
      // E11000 — lost a create race; fall through to the existing-group path.
      existing = await getGateGroup(groupRef);
      if (!existing) throw error;
    }
  }
  if (!sameAnchor(existing.anchorRef, anchorRef)) return { kind: "anchor-mismatch" };
  return { kind: "ok" };
};
