import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import request from "supertest";
import { randomBytes } from "crypto";
import { fromUint8Array, toUint8Array } from "js-base64";
import { VOPRFClient } from "@cloudflare/voprf-ts";

const env = vi.hoisted(() => ({}) as Record<string, string | undefined>);
vi.mock("../../config", () => ({ config: env }));
vi.mock("../../infra/database", () => ({ isMongoReady: () => true }));
const verifyVaultUcan = vi.fn();
vi.mock("../../domain/vault/ucan", () => ({ verifyVaultUcan: (...a: unknown[]) => verifyVaultUcan(...a) }));

import app from "../../app";
import { logger } from "../../logger";
import { resetVaultKeysForTests, VAULT_SUITE } from "../../infra/vault-keys";
import { resetVaultStoreForTests, setVaultStore } from "../../domain/vault/store";
import { createMemoryVaultStore } from "../../domain/vault/memory-store";
import type { VaultStore } from "../../domain/vault/store";

const ORIGIN = "https://docs.fileverse.io";
const A = "0x" + "a".repeat(40);
const B = "0x" + "b".repeat(40);

const cookieFrom = (res: request.Response): string =>
  ((res.headers["set-cookie"] as unknown as string[]) ?? [])
    .map((c) => c.split(";")[0])
    .find((c) => c.startsWith("fv_vault=")) ?? "";

const blindRequest = async (publicKey: string) => {
  const client = new VOPRFClient(VAULT_SUITE, toUint8Array(publicKey));
  const [, req] = await client.blind([randomBytes(32)]);
  return fromUint8Array(req.serialize());
};

describe("/vault routes", () => {
  beforeEach(() => {
    for (const k of Object.keys(env)) delete env[k];
    env.GATE_VAULT_KEY = randomBytes(32).toString("base64");
    env.VAULT_ALLOWED_ORIGINS = `${ORIGIN},http://localhost:3000`;
    resetVaultKeysForTests();
    setVaultStore(createMemoryVaultStore());
    verifyVaultUcan.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("answers an allowed preflight with credentials", async () => {
    const res = await request(app)
      .options("/vault/evaluate")
      .set("Origin", ORIGIN)
      .set("Access-Control-Request-Method", "POST")
      .set("Access-Control-Request-Headers", "content-type");
    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe(ORIGIN);
    expect(res.headers["access-control-allow-credentials"]).toBe("true");
  });

  it("gives an unknown origin no CORS headers", async () => {
    const res = await request(app)
      .options("/vault/evaluate")
      .set("Origin", "https://evil.example")
      .set("Access-Control-Request-Method", "POST");
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("keeps the wildcard on existing routes", async () => {
    const res = await request(app).get("/ping").set("Origin", "https://anything.example");
    expect(res.headers["access-control-allow-origin"]).toBe("*");
  });

  it("keeps the wildcard on a /voprf preflight", async () => {
    const res = await request(app)
      .options("/voprf/evaluate")
      .set("Origin", "https://anything.example")
      .set("Access-Control-Request-Method", "POST");
    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe("*");
    expect(res.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it("keeps the wildcard on a /gate preflight", async () => {
    const res = await request(app)
      .options("/gate/register")
      .set("Origin", "https://anything.example")
      .set("Access-Control-Request-Method", "POST");
    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe("*");
    expect(res.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it("rejects a form-encoded post with 415", async () => {
    const res = await request(app)
      .post("/vault/leave")
      .set("Origin", ORIGIN)
      .type("form")
      .send({ identityContractAddress: A });
    expect(res.status).toBe(415);
  });

  it("rejects a text/plain post with 415", async () => {
    const res = await request(app)
      .post("/vault/leave")
      .set("Origin", ORIGIN)
      .type("text/plain")
      .send("hello");
    expect(res.status).toBe(415);
  });

  it("sets Cache-Control: no-store on a vault response", async () => {
    const res = await request(app).get("/vault/session").set("Origin", ORIGIN);
    expect(res.headers["cache-control"]).toContain("no-store");
  });

  it("404s inside the vault router for an unmatched path", async () => {
    const res = await request(app).get("/vault/does-not-exist").set("Origin", ORIGIN);
    expect(res.status).toBe(404);
  });

  describe("vault store not installed", () => {
    afterEach(() => {
      // Restore so later tests in this file (which rely on beforeEach's memory
      // store) are unaffected.
      setVaultStore(createMemoryVaultStore());
    });

    it("returns 503 GATE_NOT_READY instead of a 500 in the connect-to-index window", async () => {
      resetVaultStoreForTests();
      const res = await request(app).get("/vault/session").set("Origin", ORIGIN);
      expect(res.status).toBe(503);
      expect(res.body.message).toBe("GATE_NOT_READY");
    });

    it("still answers a preflight and a 415 ahead of the store guard", async () => {
      resetVaultStoreForTests();
      const preflight = await request(app)
        .options("/vault/evaluate")
        .set("Origin", ORIGIN)
        .set("Access-Control-Request-Method", "POST");
      expect(preflight.status).toBe(204);

      const unsupported = await request(app)
        .post("/vault/leave")
        .set("Origin", ORIGIN)
        .type("text/plain")
        .send("hello");
      expect(unsupported.status).toBe(415);
    });
  });

  it("enroll sets a strict httpOnly cookie scoped to /vault", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const res = await request(app).post("/vault/enroll").set("Origin", ORIGIN).send({ ucan: "t" });
    expect(res.status).toBe(200);
    const raw = (res.headers["set-cookie"] as unknown as string[])[0];
    expect(raw).toMatch(/fv_vault=/);
    expect(raw).toMatch(/HttpOnly/);
    expect(raw).toMatch(/Secure/);
    expect(raw).toMatch(/SameSite=Strict/);
    expect(raw).toMatch(/Path=\/vault/);
    expect(raw).toMatch(/Max-Age=34560000/);
    expect(raw).not.toMatch(/Domain=/i);
    expect(res.body.keyVersion).toBe(1);
  });

  it("evaluates for an enrolled identity and refuses another", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const enrolled = await request(app).post("/vault/enroll").set("Origin", ORIGIN).send({ ucan: "t" });
    const cookie = cookieFrom(enrolled);
    const evaluationRequest = await blindRequest(enrolled.body.oprfPublicKey);

    const ok = await request(app)
      .post("/vault/evaluate")
      .set("Origin", ORIGIN)
      .set("Cookie", cookie)
      .send({ identityContractAddress: A, evaluationRequest, keyVersion: 1 });
    expect(ok.status).toBe(200);
    expect(typeof ok.body.evaluation).toBe("string");
    expect(cookieFrom(ok)).toBe(cookie);

    const other = await request(app)
      .post("/vault/evaluate")
      .set("Origin", ORIGIN)
      .set("Cookie", cookie)
      .send({ identityContractAddress: B, evaluationRequest, keyVersion: 1 });
    expect(other.status).toBe(403);
  });

  it("returns 401 without a cookie", async () => {
    const res = await request(app)
      .post("/vault/evaluate")
      .set("Origin", ORIGIN)
      .send({ identityContractAddress: A, evaluationRequest: "x", keyVersion: 1 });
    expect(res.status).toBe(401);
  });

  it("sets Retry-After on 429", async () => {
    // Frozen at a minute boundary: enforceRateLimit buckets by floor(now/60000), so an
    // unfrozen clock crossing that boundary mid-loop would split the 31 calls across two
    // windows and never trip the limit. Only Date is faked; timers/network are unaffected.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    try {
      verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
      const enrolled = await request(app).post("/vault/enroll").set("Origin", ORIGIN).send({ ucan: "t" });
      const cookie = cookieFrom(enrolled);
      const evaluationRequest = await blindRequest(enrolled.body.oprfPublicKey);
      let last: request.Response | undefined;
      for (let i = 0; i < 31; i += 1) {
        last = await request(app)
          .post("/vault/evaluate")
          .set("Origin", ORIGIN)
          .set("Cookie", cookie)
          .send({ identityContractAddress: A, evaluationRequest, keyVersion: 1 });
      }
      expect(last?.status).toBe(429);
      expect(last?.headers["retry-after"]).toBe("60");
    } finally {
      vi.useRealTimers();
    }
  });

  it("leave clears the cookie when the session empties", async () => {
    verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
    const enrolled = await request(app).post("/vault/enroll").set("Origin", ORIGIN).send({ ucan: "t" });
    const res = await request(app)
      .post("/vault/leave")
      .set("Origin", ORIGIN)
      .set("Cookie", cookieFrom(enrolled))
      .send({ identityContractAddress: A });
    expect(res.status).toBe(204);
    expect((res.headers["set-cookie"] as unknown as string[])[0]).toMatch(/fv_vault=;/);
  });

  describe("/vault/revoke-all cookie handling", () => {
    it("clears the cookie when the caller's session empties", async () => {
      verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
      const enrolled = await request(app).post("/vault/enroll").set("Origin", ORIGIN).send({ ucan: "t" });
      const cookie = cookieFrom(enrolled);

      const res = await request(app)
        .post("/vault/revoke-all")
        .set("Origin", ORIGIN)
        .set("Cookie", cookie)
        .send({ ucan: "t" });
      expect(res.status).toBe(200);
      expect((res.headers["set-cookie"] as unknown as string[])[0]).toMatch(/fv_vault=;/);
    });

    it("re-sets the cookie when the caller's session still holds another identity", async () => {
      verifyVaultUcan.mockResolvedValueOnce({ identityContractAddress: A });
      const enrolledA = await request(app).post("/vault/enroll").set("Origin", ORIGIN).send({ ucan: "tA" });
      const cookie = cookieFrom(enrolledA);

      verifyVaultUcan.mockResolvedValueOnce({ identityContractAddress: B });
      await request(app)
        .post("/vault/enroll")
        .set("Origin", ORIGIN)
        .set("Cookie", cookie)
        .send({ ucan: "tB" });

      verifyVaultUcan.mockResolvedValueOnce({ identityContractAddress: A });
      const res = await request(app)
        .post("/vault/revoke-all")
        .set("Origin", ORIGIN)
        .set("Cookie", cookie)
        .send({ ucan: "revokeA" });
      expect(res.status).toBe(200);
      const setCookie = (res.headers["set-cookie"] as unknown as string[] | undefined)?.[0];
      expect(setCookie).toMatch(/fv_vault=[^;]+;/);
      expect(setCookie).not.toMatch(/fv_vault=;/);
    });

    it("propagates a store error from the follow-up listSession without clearing the cookie", async () => {
      const base = createMemoryVaultStore();
      let findLiveSessionCalls = 0;
      const store: VaultStore = {
        ...base,
        findLiveSession: async (id, now) => {
          findLiveSessionCalls += 1;
          if (findLiveSessionCalls > 1) throw new Error("store unavailable");
          return base.findLiveSession(id, now);
        },
      };
      setVaultStore(store);
      // The follow-up listSession throw hits the central handler's unhandled-error
      // branch, which logs at error level; muted here like the malformed-JSON tests
      // below so a deliberately-triggered failure doesn't print in suite output.
      vi.spyOn(logger, "error").mockImplementation(() => logger);

      verifyVaultUcan.mockResolvedValue({ identityContractAddress: A });
      const enrolled = await request(app).post("/vault/enroll").set("Origin", ORIGIN).send({ ucan: "t" });
      const cookie = cookieFrom(enrolled);

      const res = await request(app)
        .post("/vault/revoke-all")
        .set("Origin", ORIGIN)
        .set("Cookie", cookie)
        .send({ ucan: "t" });
      expect(res.status).toBeGreaterThanOrEqual(500);
      expect(res.headers["set-cookie"]).toBeUndefined();
    });
  });

  describe("malformed JSON body", () => {
    it("returns 400 for /vault/enroll without logging the body", async () => {
      const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => logger);
      const errorSpy = vi.spyOn(logger, "error").mockImplementation(() => logger);
      const res = await request(app)
        .post("/vault/enroll")
        .set("Origin", ORIGIN)
        .set("Content-Type", "application/json")
        .send('{"ucan":"LEAKED_SECRET_VALUE"');
      expect(res.status).toBe(400);
      const logged = JSON.stringify([...warnSpy.mock.calls, ...errorSpy.mock.calls]);
      expect(logged).not.toContain("LEAKED_SECRET_VALUE");
    });

    it("returns 400 for an existing /gate route without logging the body", async () => {
      const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => logger);
      const errorSpy = vi.spyOn(logger, "error").mockImplementation(() => logger);
      const res = await request(app)
        .post("/gate/register")
        .set("Content-Type", "application/json")
        .send('{"docId":"LEAKED_SECRET_VALUE"');
      expect(res.status).toBe(400);
      const logged = JSON.stringify([...warnSpy.mock.calls, ...errorSpy.mock.calls]);
      expect(logged).not.toContain("LEAKED_SECRET_VALUE");
    });
  });
});
