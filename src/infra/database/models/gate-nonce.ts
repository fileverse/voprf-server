// Single-use /challenge nonces. TTL index sweeps expired rows (~every 60s).
import { Schema, model } from "mongoose";

/** Nonce live window (seconds): TTL expiry and the consume/list $gte filter. */
export const NONCE_TTL_SECONDS = 300;

export interface GateNonceRecord {
  nonce: string;
  docId: string;
  createdAt: Date;
}

const GateNonceSchema = new Schema<GateNonceRecord>(
  {
    nonce: { type: String, required: true, unique: true },
    docId: { type: String, required: true, index: true },
    createdAt: { type: Date, default: Date.now, expires: NONCE_TTL_SECONDS },
  },
  { collection: "gate_nonces" }
);

const GateNonce = model<GateNonceRecord>("GateNonce", GateNonceSchema);

export default GateNonce;
