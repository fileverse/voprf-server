import { createHash, randomBytes } from "crypto";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { getVaultStore } from "./store";
import { verifyVaultUcan } from "./ucan";
import { enforceRateLimit } from "./rate-limit";
import { evaluateForIdentity, getVaultPublicKey } from "./evaluate";

export const SESSION_IDLE_MS = 365 * 24 * 60 * 60 * 1000;

export const newSessionToken = (): string => randomBytes(32).toString("base64url");

export const hashSessionToken = (token: string): string =>
  createHash("sha256").update(token).digest("hex");

const idleExpiry = (now: Date) => new Date(now.getTime() + SESSION_IDLE_MS);

// Coarse "browser on OS" label for the settings list; never the raw header.
const userAgentHint = (ua?: string): string | undefined => {
  if (!ua) return undefined;
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Firefox\//.test(ua)
      ? "Firefox"
      : /Chrome\//.test(ua)
        ? "Chrome"
        : /Safari\//.test(ua)
          ? "Safari"
          : "Browser";
  const os = /iPhone|iPad/.test(ua)
    ? "iOS"
    : /Android/.test(ua)
      ? "Android"
      : /Mac OS X/.test(ua)
        ? "macOS"
        : /Windows/.test(ua)
          ? "Windows"
          : /Linux/.test(ua)
            ? "Linux"
            : "Unknown";
  return `${browser} on ${os}`;
};

const noSession = (): never => throwError({ code: 401, message: GateErrorCode.VAULT_NO_SESSION });

export const authorizeSession = async (
  cookieToken: string | undefined,
  now: Date = new Date()
): Promise<{ sessionId: string; identities: string[] }> => {
  if (!cookieToken) return noSession();
  const sessionId = hashSessionToken(cookieToken);
  const session = await getVaultStore().findLiveSession(sessionId, now);
  if (!session) return noSession();
  await getVaultStore().touch(sessionId, null, now, idleExpiry(now));
  return { sessionId, identities: session.identities.map((i) => i.identityContractAddress) };
};

export const enroll = async ({
  ucan,
  cookieToken,
  userAgent,
  now = new Date(),
}: {
  ucan: string;
  cookieToken?: string;
  userAgent?: string;
  now?: Date;
}): Promise<{
  cookieToken: string;
  identityContractAddress: string;
  oprfPublicKey: string;
  keyVersion: number;
}> => {
  const { identityContractAddress } = await verifyVaultUcan(ucan, now);
  await enforceRateLimit("enroll", identityContractAddress, now);
  const { publicKey, keyVersion } = await getVaultPublicKey(identityContractAddress);

  const store = getVaultStore();
  let token = cookieToken;
  let sessionId = token ? hashSessionToken(token) : undefined;
  const existing = sessionId ? await store.findLiveSession(sessionId, now) : null;
  if (!existing) {
    token = newSessionToken();
    sessionId = hashSessionToken(token);
    await store.createSession({
      id: sessionId,
      identities: [],
      createdAt: now,
      lastSeenAt: now,
      expiresAt: idleExpiry(now),
      userAgentHint: userAgentHint(userAgent),
    });
  }
  await store.addIdentity(sessionId as string, identityContractAddress, now, idleExpiry(now));
  return {
    cookieToken: token as string,
    identityContractAddress,
    oprfPublicKey: publicKey,
    keyVersion,
  };
};

export const evaluate = async ({
  cookieToken,
  identityContractAddress,
  evaluationRequest,
  keyVersion,
  now = new Date(),
}: {
  cookieToken?: string;
  identityContractAddress: string;
  evaluationRequest: string;
  keyVersion: number;
  now?: Date;
}) => {
  const addr = identityContractAddress.toLowerCase();
  const { sessionId, identities } = await authorizeSession(cookieToken, now);
  if (!identities.includes(addr)) {
    return throwError({ code: 403, message: GateErrorCode.VAULT_NOT_ENROLLED });
  }
  await enforceRateLimit("evaluate", sessionId, now);
  const result = await evaluateForIdentity(addr, evaluationRequest, keyVersion);
  await getVaultStore().touch(sessionId, addr, now, idleExpiry(now));
  return result;
};

export const leave = async ({
  cookieToken,
  identityContractAddress,
  now = new Date(),
}: {
  cookieToken?: string;
  identityContractAddress: string;
  now?: Date;
}): Promise<{ sessionDeleted: boolean }> => {
  const { sessionId } = await authorizeSession(cookieToken, now);
  const store = getVaultStore();
  const { remaining } = await store.removeIdentity(sessionId, identityContractAddress.toLowerCase());
  if (remaining === 0) {
    await store.deleteSession(sessionId);
    return { sessionDeleted: true };
  }
  return { sessionDeleted: false };
};

export const revokeAll = async ({
  cookieToken,
  ucan,
  now = new Date(),
}: {
  cookieToken?: string;
  ucan: string;
  now?: Date;
}): Promise<{ sessionsAffected: number }> => {
  await authorizeSession(cookieToken, now);
  const { identityContractAddress } = await verifyVaultUcan(ucan, now);
  await enforceRateLimit("revokeAll", identityContractAddress, now);
  const sessionsAffected = await getVaultStore().removeIdentityEverywhere(identityContractAddress);
  return { sessionsAffected };
};

export const listSession = async (cookieToken: string | undefined, now: Date = new Date()) => {
  if (!cookieToken) return noSession();
  const session = await getVaultStore().findLiveSession(hashSessionToken(cookieToken), now);
  if (!session) return noSession();
  return {
    identities: session.identities.map((i) => ({
      identityContractAddress: i.identityContractAddress,
      enrolledAt: i.enrolledAt.toISOString(),
      lastUsedAt: i.lastUsedAt.toISOString(),
    })),
  };
};
