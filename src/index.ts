import { config } from "./config";

import app from "./app";
import { logger } from "./logger";
import { loadGateKeys, getGateMasterKey } from "./infra/gate-keys";
import { loadVaultKeys, getVaultKeyConfig } from "./infra/vault-keys";
import { connectGateDatastore } from "./infra/database";

const port = config.PORT || 8001;

async function startServer() {
  try {
    // Fatal: a malformed gate key (or the dev override in production) must refuse to boot.
    loadGateKeys();
    if (!getGateMasterKey()) {
      logger.warn("gate: GATE_MASTER_KEY is not set — /register, /share and /release will respond 503");
    }

    loadVaultKeys();
    if (!getVaultKeyConfig()) {
      logger.warn("vault: GATE_VAULT_KEY unset, /vault disabled");
    }

    const hasAllowedOrigin = (config.VAULT_ALLOWED_ORIGINS ?? "").split(",").some((o) => o.trim());
    if (!hasAllowedOrigin) {
      logger.warn("vault: VAULT_ALLOWED_ORIGINS unset or empty, /vault browser calls will fail CORS");
    }

    if (config.MONGO_URI) {
      void connectGateDatastore(config.MONGO_URI);
    } else {
      logger.warn("gate: MONGO_URI is not set — /gate routes will respond 503");
    }

    // Non-fatal: the viem client is created lazily, so missing NETWORK/RPC_URL only
    // fails the gate's owner-verification path — VOPRF stays live.
    if (!config.NETWORK || !config.RPC_URL) {
      logger.warn(
        "gate: NETWORK/RPC_URL not fully configured — gate chain reads (owner verification) will fail until set"
      );
    }

    app.listen(port, () => logger.info(`🚀 Server ready on port ${port}`));
  } catch (error) {
    logger.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();

export default app;
