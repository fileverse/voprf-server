import cors from "cors";
import { config } from "../../config";

const allowedOrigins = (): string[] =>
  (config.VAULT_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);

// Credentialed routes cannot use the wildcard; unknown origins get no CORS headers.
export const vaultCors = cors({
  origin: (origin, callback) => {
    callback(null, !!origin && allowedOrigins().includes(origin));
  },
  credentials: true,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"],
  exposedHeaders: ["Retry-After"],
  maxAge: 600,
});
