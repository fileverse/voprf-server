// Prints a base64-encoded 32-byte GATE_MASTER_KEY.
// Usage: npx ts-node --transpile-only scripts/generate-gate-master-key.ts
import { randomBytes } from "crypto";

console.log(randomBytes(32).toString("base64"));
