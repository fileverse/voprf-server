// Prints a GATE_VAULT_KEY=<base64 32-byte key> line for .env.
// Usage: npx ts-node --transpile-only scripts/generateVaultKey.ts
import { randomBytes } from "crypto";

console.log("GATE_VAULT_KEY=" + randomBytes(32).toString("base64"));
