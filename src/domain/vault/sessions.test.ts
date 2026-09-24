import { describe, it, expect, beforeEach, vi } from "vitest";
import { randomBytes } from "crypto";
import { fromUint8Array, toUint8Array } from "js-base64";
import { VOPRFClient, Evaluation } from "@cloudflare/voprf-ts";

const env = vi.hoisted(() => ({}) as Record<string, string | undefined>);
vi.mock("../../config", () => ({ config: env }));

const verifyVaultUcan = vi.fn();
vi.mock("./ucan", () => ({ verifyVaultUcan: (...a: unknown[]) => verifyVaultUcan(...a) }));

import { resetVaultKeysForTests, VAULT_SUITE } from "../../infra/vault-keys";
import { getVaultStore, setVaultStore } from "./store";
import { createMemoryVaultStore } from "./memory-store";
import { getVaultPublicKey } from "./evaluate";
import {
  authorizeSession,
  enroll,
  evaluate,
  hashSessionToken,
  leave,
  listSession,
  revokeAll,
  SESSION_IDLE_MS,
} from "./sessions";

const A = "0x" + "a".repeat(40);
const B = "0x" + "b".repeat(40);
// Same bytes as A, alternating case on every letter.
const MIXED_CASE_A = "0x" + "aA".repeat(20);

// A real, single-use VOPRF evaluation request against an identity's current key,
// built the same way a client would (mirrors evaluate.test.ts's roundTrip helper).
const buildRequest = async (identity: string) => {
  const { publicKey } = await getVaultPublicKey(identity);
  const client = new VOPRFClient(VAULT_SUITE, toUint8Array(publicKey));
  const [finalizeData, request] = await client.blind([randomBytes(32)]);
  return { client, finalizeData, evaluationRequest: fromUint8Array(request.serialize()) };
};

describe("vault sessions", () => {
  beforeEach(() => {
    for (const k of Object.keys(env)) delete env[k];
    env.GATE_VAULT_KEY = randomBytes(32).toString("base64");
    resetVaultKeysForTests();
    setVaultStore(createMemoryVaultStore());
    verifyVaultUcan.mockReset();
  });

  it("enroll creates a session and returns the public key", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const res = await enroll({ ucan: "t" });
    expect(res.cookieToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(res.keyVersion).toBe(1);
    expect((await authorizeSession(res.cookieToken)).identities).toEqual([A]);
  });

  it("enroll with a live cookie adds to the same session", async () => {
    verifyVaultUcan.mockResolvedValueOnce({ identityContractAddress: A });
    const first = await enroll({ ucan: "t1" });
    verifyVaultUcan.mockResolvedValueOnce({ identityContractAddress: B });
    const second = await enroll({ ucan: "t2", cookieToken: first.cookieToken });
    expect(second.cookieToken).toBe(first.cookieToken);
    expect((await authorizeSession(first.cookieToken)).identities).toEqual([A, B]);
  });

  it("enroll with a dead cookie starts a new session", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const res = await enroll({ ucan: "t", cookieToken: "does-not-exist" });
    expect(res.cookieToken).not.toBe("does-not-exist");
  });

  it("rejects a missing or expired cookie with 401", async () => {
    await expect(authorizeSession(undefined)).rejects.toMatchObject({ code: 401 });
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const t0 = new Date(0);
    const { cookieToken } = await enroll({ ucan: "t", now: t0 });
    await expect(authorizeSession(cookieToken, new Date(SESSION_IDLE_MS + 1))).rejects.toMatchObject({ code: 401 });
  });

  it("slides the idle window on use", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const { cookieToken } = await enroll({ ucan: "t", now: new Date(0) });
    await authorizeSession(cookieToken, new Date(SESSION_IDLE_MS - 1000));
    await expect(authorizeSession(cookieToken, new Date(SESSION_IDLE_MS + 1000))).resolves.toBeTruthy();
  });

  it("leave removes the identity and deletes an empty session", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const { cookieToken } = await enroll({ ucan: "t" });
    expect(await leave({ cookieToken, identityContractAddress: A })).toEqual({ sessionDeleted: true });
    await expect(authorizeSession(cookieToken)).rejects.toMatchObject({ code: 401 });
  });

  it("revoke-all removes the identity from every session", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const one = await enroll({ ucan: "t1" });
    const two = await enroll({ ucan: "t2" });
    expect(await revokeAll({ cookieToken: one.cookieToken, ucan: "t3" })).toEqual({ sessionsAffected: 2 });
    await expect(authorizeSession(two.cookieToken)).rejects.toMatchObject({ code: 401 });
  });

  it("revoke-all requires a live session", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    await expect(revokeAll({ cookieToken: undefined, ucan: "t" })).rejects.toMatchObject({ code: 401 });
  });

  it("lists enrolled identities", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const { cookieToken } = await enroll({ ucan: "t" });
    const listed = await listSession(cookieToken);
    expect(listed.identities.map((i) => i.identityContractAddress)).toEqual([A]);
  });

  it("rate-limits enroll per identity", async () => {
    // Fixed `now`: enforceRateLimit buckets by floor(now/windowMs), so a real clock
    // crossing the hourly bucket boundary mid-loop could split the 11 calls across
    // two windows and never trip the limit.
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const now = new Date(0);
    for (let i = 0; i < 10; i += 1) await enroll({ ucan: `t${i}`, now });
    await expect(enroll({ ucan: "t10", now })).rejects.toMatchObject({ code: 429 });
  });

  it("evaluate rejects an identity not enrolled in the session with 403", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const { cookieToken } = await enroll({ ucan: "t" });
    const { evaluationRequest } = await buildRequest(B);
    await expect(
      evaluate({ cookieToken, identityContractAddress: B, evaluationRequest, keyVersion: 1 })
    ).rejects.toMatchObject({ code: 403, message: "VAULT_NOT_ENROLLED" });
  });

  it("evaluate accepts a checksummed address of an enrolled identity", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const { cookieToken } = await enroll({ ucan: "t" });
    const { client, finalizeData, evaluationRequest } = await buildRequest(A);
    const res = await evaluate({
      cookieToken,
      identityContractAddress: MIXED_CASE_A,
      evaluationRequest,
      keyVersion: 1,
    });
    const [output] = await client.finalize(
      finalizeData,
      Evaluation.deserialize(VAULT_SUITE, toUint8Array(res.evaluation))
    );
    expect(output).toBeInstanceOf(Uint8Array);
    expect(res.currentKeyVersion).toBe(1);
  });

  it("rate-limits evaluate at 30 per minute per session", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const now = new Date(0);
    const { cookieToken } = await enroll({ ucan: "t", now });
    const { evaluationRequest } = await buildRequest(A);
    for (let i = 0; i < 30; i += 1) {
      await evaluate({ cookieToken, identityContractAddress: A, evaluationRequest, keyVersion: 1, now });
    }
    await expect(
      evaluate({ cookieToken, identityContractAddress: A, evaluationRequest, keyVersion: 1, now })
    ).rejects.toMatchObject({ code: 429, message: "RATE_LIMITED", retryAfterSeconds: expect.any(Number) });
  });

  it("evaluate updates lastUsedAt for the identity in the store", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const enrollNow = new Date(0);
    const { cookieToken } = await enroll({ ucan: "t", now: enrollNow });
    const sessionId = hashSessionToken(cookieToken);
    const before = await getVaultStore().findLiveSession(sessionId, enrollNow);
    const beforeLastUsed = before!.identities.find((i) => i.identityContractAddress === A)!.lastUsedAt.getTime();

    const { evaluationRequest } = await buildRequest(A);
    const evalNow = new Date(enrollNow.getTime() + 1000);
    await evaluate({ cookieToken, identityContractAddress: A, evaluationRequest, keyVersion: 1, now: evalNow });

    const after = await getVaultStore().findLiveSession(sessionId, evalNow);
    const afterLastUsed = after!.identities.find((i) => i.identityContractAddress === A)!.lastUsedAt.getTime();
    expect(afterLastUsed).toBe(evalNow.getTime());
    expect(afterLastUsed).toBeGreaterThan(beforeLastUsed);
  });
});
