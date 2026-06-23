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
