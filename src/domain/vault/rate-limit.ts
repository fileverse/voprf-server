import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { getVaultStore } from "./store";

export const VAULT_LIMITS = {
  evaluate: { limit: 30, windowSeconds: 60 },
  enroll: { limit: 10, windowSeconds: 3600 },
  revokeAll: { limit: 5, windowSeconds: 3600 },
} as const;

export const enforceRateLimit = async (
  bucket: keyof typeof VAULT_LIMITS,
  subject: string,
  now: Date = new Date()
): Promise<void> => {
  const { limit, windowSeconds } = VAULT_LIMITS[bucket];
  const windowMs = windowSeconds * 1000;
  const windowStart = Math.floor(now.getTime() / windowMs) * windowMs;
  const count = await getVaultStore().incrementCounter(
    `${bucket}:${subject}:${windowStart}`,
    new Date(windowStart + 2 * windowMs)
  );
  if (count > limit) {
    try {
      throwError({ code: 429, message: GateErrorCode.RATE_LIMITED });
    } catch (error) {
      (error as { retryAfterSeconds?: number }).retryAfterSeconds = Math.ceil(
        (windowStart + windowMs - now.getTime()) / 1000
      );
      throw error;
    }
  }
};
