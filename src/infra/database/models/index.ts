// Gate model barrel. No connection side-effect — the gate connects explicitly via connectGateDatastore.
import GateDoc from "./gate-doc";
import GateGroup from "./gate-group";
import GateNonce, { NONCE_TTL_SECONDS } from "./gate-nonce";
import VaultSession from "./vault-session";
import VaultUcanNonce from "./vault-ucan-nonce";
import VaultRateCounter from "./vault-rate-counter";

export type {
  GateAnchorRef,
  GateAcceptedRoot,
  GateBinding,
  GateDocRecord,
} from "./gate-doc";
export type { GateGroupRecord } from "./gate-group";
export type { GateNonceRecord } from "./gate-nonce";
export type { VaultSessionDoc } from "./vault-session";

export { GateDoc, GateGroup, GateNonce, NONCE_TTL_SECONDS, VaultSession, VaultUcanNonce, VaultRateCounter };
