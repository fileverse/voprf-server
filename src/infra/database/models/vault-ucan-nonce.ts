// Single-use jti values from VAULT UCANs. The unique index is the replay guard;
// consumeNonce relies on its duplicate-key error.
import { Schema, model } from "mongoose";

export interface VaultUcanNonceDoc {
  nonce: string;
  identityContractAddress: string;
  expiresAt: Date;
}

const VaultUcanNonceSchema = new Schema<VaultUcanNonceDoc>(
  {
    nonce: { type: String, required: true, unique: true },
    identityContractAddress: { type: String, required: true },
    expiresAt: { type: Date, required: true, expires: 0 },
  },
  { collection: "vault_ucan_nonces" }
);

const VaultUcanNonce = model<VaultUcanNonceDoc>("VaultUcanNonce", VaultUcanNonceSchema);

export default VaultUcanNonce;
