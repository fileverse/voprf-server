import { Schema, model } from "mongoose";

export interface VaultSessionDoc {
  _id: string;
  identities: { identityContractAddress: string; enrolledAt: Date; lastUsedAt: Date }[];
  createdAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
  userAgentHint?: string;
}

const VaultSessionSchema = new Schema<VaultSessionDoc>(
  {
    _id: { type: String, required: true },
    identities: [
      {
        _id: false,
        identityContractAddress: { type: String, required: true },
        enrolledAt: { type: Date, required: true },
        lastUsedAt: { type: Date, required: true },
      },
    ],
    createdAt: { type: Date, required: true },
    lastSeenAt: { type: Date, required: true },
    // TTL at the stored instant; sliding because every authorized call rewrites it.
    expiresAt: { type: Date, required: true, expires: 0 },
    userAgentHint: { type: String },
  },
  { collection: "vault_sessions" }
);

VaultSessionSchema.index({ "identities.identityContractAddress": 1 });

const VaultSession = model<VaultSessionDoc>("VaultSession", VaultSessionSchema);

export default VaultSession;
