// Shared per-doc read used by register/enroll/revoke — the one query by docId.
import { GateDoc } from "../../infra/database/models";
import type { GateDocRecord } from "../../infra/database/models";

export const getGateDoc = async (docId: string): Promise<GateDocRecord | null> =>
  GateDoc.findOne({ docId }).lean<GateDocRecord | null>();
