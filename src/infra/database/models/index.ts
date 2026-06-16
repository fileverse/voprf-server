// Gate model barrel. No connection side-effect — the gate connects explicitly via connectGateDatastore.
import GateDoc from "./gate-doc";
import GateGroup from "./gate-group";
import GateNonce, { NONCE_TTL_SECONDS } from "./gate-nonce";

export type {
  GateAnchorRef,
  GateAcceptedRoot,
  GateBinding,
  GateDocRecord,
} from "./gate-doc";
export type { GateGroupRecord } from "./gate-group";
export type { GateNonceRecord } from "./gate-nonce";

export { GateDoc, GateGroup, GateNonce, NONCE_TTL_SECONDS };
