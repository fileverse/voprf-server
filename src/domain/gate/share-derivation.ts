// gateShare = HMAC-SHA256(k_gate[v], framed anchor‖epoch) (§4). Derived on demand,
// never stored. The PRF input is the on-chain ANCHOR, not docId — a squatter who
// registers the same docId on their own portal must derive different bytes (D-1).
import { createHmac } from "crypto";
import type { GateAnchorRef } from "../../infra/database/models";

const DOMAIN_TAG = "fv-gate-share-v1";

const uint64BE = (value: number, label: string): Buffer => {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`gate share derivation: ${label} out of range: ${value}`);
  }
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(value));
  return buf;
};

const portalAddressBytes = (portalAddress: string): Buffer => {
  const hex = portalAddress.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(hex)) {
    throw new Error("gate share derivation: portalAddress is not a 20-byte hex address");
  }
  return Buffer.from(hex, "hex");
};

// Fixed-width fields after the NUL-terminated tag make the encoding injective: no
// two distinct (chainId, portal, fileId, epoch) tuples collide on the PRF input.
export const deriveGateShare = (masterKey: Buffer, anchorRef: GateAnchorRef, epoch: number): string => {
  // HMAC silently accepts any key length, so fail loudly on a wrong-length key.
  if (masterKey.length !== 32) {
    throw new Error("gate share derivation: master key must be exactly 32 bytes");
  }
  const input = Buffer.concat([
    Buffer.from(DOMAIN_TAG, "utf8"),
    Buffer.from([0]),
    uint64BE(anchorRef.chainId, "chainId"),
    portalAddressBytes(anchorRef.portalAddress),
    uint64BE(anchorRef.fileId, "fileId"),
    uint64BE(epoch, "epoch"),
  ]);
  return createHmac("sha256", masterKey).update(input).digest("base64");
};
