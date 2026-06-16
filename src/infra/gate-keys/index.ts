// k_gate master key (§4). The Buffer is module-private so a config dump can't leak
// key bytes — getGateMasterKey() is the only egress. Loaded once at boot; misconfig
// (a malformed key, or the dev override in production) kills the process. v1 uses a
// single canonical key — versioning/rotation is deferred.
import { config } from "../../config";

let masterKeyPrivate: Buffer | undefined;
let loaded = false;

const parseMasterKey = (raw: string | undefined): Buffer | undefined => {
  if (!raw) return undefined;
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error("gate keys: GATE_MASTER_KEY must decode to exactly 32 bytes");
  }
  return key;
};

export const loadGateKeys = (): void => {
  if (config.GATE_DEV_OWNER_DID_OVERRIDE && config.NODE_ENV === "production") {
    throw new Error(
      "gate keys: GATE_DEV_OWNER_DID_OVERRIDE bypasses on-chain owner verification and must NOT be set in production"
    );
  }
  if (config.PRIVY_VERIFICATION_KEY && config.NODE_ENV === "production") {
    throw new Error(
      "gate keys: PRIVY_VERIFICATION_KEY enables offline (local-SPKI) identity-token verification and must NOT be set in production"
    );
  }
  if (loaded) return;
  // A missing key is non-fatal (gate routes 503 until set); a malformed one throws.
  masterKeyPrivate = parseMasterKey(config.GATE_MASTER_KEY);
  loaded = true;
};

/** The single master key, or undefined if GATE_MASTER_KEY is unset. The only key egress. */
export const getGateMasterKey = (): Buffer | undefined => {
  loadGateKeys();
  return masterKeyPrivate;
};
