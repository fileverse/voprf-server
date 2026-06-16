// Shared per-group read used by group register/enroll/revoke and /release's union
// resolution — the one query by groupRef. Mirrors get.ts.
import { GateGroup } from "../../infra/database/models";
import type { GateGroupRecord } from "../../infra/database/models";

export const getGateGroup = async (groupRef: string): Promise<GateGroupRecord | null> =>
  GateGroup.findOne({ groupRef }).lean<GateGroupRecord | null>();
