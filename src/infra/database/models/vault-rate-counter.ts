// Fixed-window rate-limit counters keyed by session or identity (never IP).
import { Schema, model } from "mongoose";

export interface VaultRateCounterDoc {
  key: string;
  count: number;
  expiresAt: Date;
}

const VaultRateCounterSchema = new Schema<VaultRateCounterDoc>(
  {
    key: { type: String, required: true, unique: true },
    count: { type: Number, required: true, default: 0 },
    expiresAt: { type: Date, required: true, expires: 0 },
  },
  { collection: "vault_rate_counters" }
);

const VaultRateCounter = model<VaultRateCounterDoc>("VaultRateCounter", VaultRateCounterSchema);

export default VaultRateCounter;
