// /group/:groupRef/reinstate — lift a group revocation. Mirrors reinstate.ts.
import { GateGroup } from "../../infra/database/models";
import { getGateGroup } from "./group-get";

export type GroupReinstateOutcome = { kind: "ok" } | { kind: "unknown-group" };

export const reinstateGateGroupMember = async (
  groupRef: string,
  idHash: string
): Promise<GroupReinstateOutcome> => {
  const group = await getGateGroup(groupRef);
  if (!group) return { kind: "unknown-group" };
  await GateGroup.updateOne({ groupRef }, { $pull: { revokedIdHashes: idHash } });
  return { kind: "ok" };
};
