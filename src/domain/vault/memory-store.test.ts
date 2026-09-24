import { describe, it, expect } from "vitest";
import { createMemoryVaultStore } from "./memory-store";

const A = "0x" + "a".repeat(40);
const B = "0x" + "b".repeat(40);
const t = (ms: number) => new Date(ms);

describe("memory vault store", () => {
  it("creates, finds, expires sessions", async () => {
    const s = createMemoryVaultStore();
    await s.createSession({ id: "s1", identities: [], createdAt: t(0), lastSeenAt: t(0), expiresAt: t(1000) });
    expect(await s.findLiveSession("s1", t(500))).not.toBeNull();
    expect(await s.findLiveSession("s1", t(1000))).toBeNull();
  });

  it("adds identities idempotently and removes them", async () => {
    const s = createMemoryVaultStore();
    await s.createSession({ id: "s1", identities: [], createdAt: t(0), lastSeenAt: t(0), expiresAt: t(9e12) });
    await s.addIdentity("s1", A, t(1), t(9e12));
    await s.addIdentity("s1", A, t(2), t(9e12));
    await s.addIdentity("s1", B, t(3), t(9e12));
    expect((await s.findLiveSession("s1", t(4)))?.identities.map((i) => i.identityContractAddress)).toEqual([A, B]);
    expect(await s.removeIdentity("s1", A)).toEqual({ remaining: 1 });
  });

  it("removes an identity from every session", async () => {
    const s = createMemoryVaultStore();
    for (const id of ["s1", "s2"]) {
      await s.createSession({ id, identities: [], createdAt: t(0), lastSeenAt: t(0), expiresAt: t(9e12) });
      await s.addIdentity(id, A, t(1), t(9e12));
    }
    expect(await s.removeIdentityEverywhere(A)).toBe(2);
    // A session emptied by revoke-all is deleted outright, invalidating that cookie,
    // rather than surviving as a live session enrolled in nothing.
    expect(await s.findLiveSession("s2", t(2))).toBeNull();
  });

  it("consumes a nonce once", async () => {
    const s = createMemoryVaultStore();
    expect(await s.consumeNonce("n", A, t(9e12))).toBe(true);
    expect(await s.consumeNonce("n", A, t(9e12))).toBe(false);
  });

  it("increments counters", async () => {
    const s = createMemoryVaultStore();
    expect(await s.incrementCounter("k", t(9e12))).toBe(1);
    expect(await s.incrementCounter("k", t(9e12))).toBe(2);
  });
});
