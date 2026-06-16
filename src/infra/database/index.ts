// The gate datastore connection. Deliberately NOT storage-v2's fail-fast connect:
// the gate must come up even when Mongo is down (VOPRF stays live; /gate 503s until
// this succeeds), so the connect is non-fatal and retries forever with capped backoff.
import mongoose from "mongoose";
import { GateDoc, GateGroup, GateNonce } from "./models";
import { logger } from "../../logger";

export const isMongoReady = (): boolean => mongoose.connection.readyState === 1;

const CONNECT_RETRY_MAX_DELAY_MS = 30_000;

export const connectGateDatastore = async (mongoUri: string): Promise<void> => {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await mongoose.connect(mongoUri);
      // Unique indexes must exist before traffic (registerGateDoc relies on the docId
      // E11000). createIndexes — NOT Model.init() — re-runs per attempt; init() caches
      // rejections and would wedge the retry loop.
      await Promise.all([GateDoc.createIndexes(), GateGroup.createIndexes(), GateNonce.createIndexes()]);
      logger.info("gate: datastore connected");
      return;
    } catch (error) {
      const delayMs = Math.min(attempt * 2_000, CONNECT_RETRY_MAX_DELAY_MS);
      logger.error(`gate: datastore connection failed (attempt ${attempt}) — retrying in ${delayMs}ms`, error);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
};
