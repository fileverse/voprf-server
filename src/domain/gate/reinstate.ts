// /reinstate — lift a revocation so a re-invited identity can enroll again.
// Pure $pull of the idHash from the denylist; idempotent (absent → no-op).
import { GateDoc } from "../../infra/database/models";
import { getGateDoc } from "./get";

export type ReinstateOutcome = { kind: "ok" } | { kind: "unknown-doc" };

export const reinstateGateMember = async (
  docId: string,
  idHash: string
): Promise<ReinstateOutcome> => {
  const doc = await getGateDoc(docId);
  if (!doc) return { kind: "unknown-doc" };
  await GateDoc.updateOne({ docId }, { $pull: { revokedIdHashes: idHash } });
  return { kind: "ok" };
};
