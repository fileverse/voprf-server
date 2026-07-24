import * as ucans from "@ucans/ucans";
import { config } from "../../config";

let masterKeyPrivate: Buffer | undefined;
let signingKeypair: ucans.EdKeypair | undefined;
let loaded = false;

const parseMasterKey = (raw: string | undefined): Buffer | undefined => {
  if (!raw) return undefined;
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error("gate keys: GATE_MASTER_KEY must decode to exactly 32 bytes");
  }
  return key;
};

// The gate's Ed25519 UCAN-signing identity (its FIRST asymmetric key). A missing key is
// non-fatal — the edit-admission UCAN is simply not minted (release still returns shares);
// a malformed one throws at boot so a misconfigured deploy fails loudly.
const parseSigningKey = (raw: string | undefined): ucans.EdKeypair | undefined => {
  if (!raw) return undefined;
  return ucans.EdKeypair.fromSecretKey(raw);
};

export const loadGateKeys = (): void => {
  if (loaded) return;
  masterKeyPrivate = parseMasterKey(config.GATE_MASTER_KEY);
  signingKeypair = parseSigningKey(config.GATE_SIGNING_KEY);
  loaded = true;
};

/** The single master key, or undefined if GATE_MASTER_KEY is unset. The only HMAC key egress. */
export const getGateMasterKey = (): Buffer | undefined => {
  loadGateKeys();
  return masterKeyPrivate;
};

/** The gate's UCAN-signing keypair, or undefined if GATE_SIGNING_KEY is unset. */
export const getGateSigningKeypair = (): ucans.EdKeypair | undefined => {
  loadGateKeys();
  return signingKeypair;
};

/** The gate's DID (did:key), or undefined if unconfigured. */
export const getGateSigningDid = (): string | undefined => {
  loadGateKeys();
  return signingKeypair?.did();
};
