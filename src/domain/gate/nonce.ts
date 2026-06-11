// Single-use /challenge nonces against the gate-nonce model. All non-secret.
import { randomBytes } from "crypto";
import { GateNonce, NONCE_TTL_SECONDS } from "../../infra/database/models";

/**
 * 0x-prefixed 16-byte hex — encodes through the proof library's first toBigInt
 * branch (plain hex), dodging encodeBytes32String's 31-byte ceiling.
 */
export const createGateNonce = async (docId: string): Promise<string> => {
  const nonce = `0x${randomBytes(16).toString("hex")}`;
  await GateNonce.create({ nonce, docId });
  return nonce;
};

const liveWindowStart = (): Date => new Date(Date.now() - NONCE_TTL_SECONDS * 1000);

// The createdAt live-window filter is needed IN ADDITION to the TTL index: Mongo
// sweeps the TTL collection only ~every 60s, so a not-yet-swept expired nonce must
// still be rejected explicitly here.
export const listLiveNonces = async (docId: string): Promise<string[]> => {
  const records = await GateNonce.find({ docId, createdAt: { $gte: liveWindowStart() } }).lean();
  return records.map((r) => r.nonce);
};

/** Single-use: atomic delete; false = wrong doc, expired, or already consumed. */
export const consumeGateNonce = async (docId: string, nonce: string): Promise<boolean> => {
  const deleted = await GateNonce.findOneAndDelete({ nonce, docId, createdAt: { $gte: liveWindowStart() } });
  return deleted !== null;
};
