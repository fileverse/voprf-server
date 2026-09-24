import type { VaultSessionRecord, VaultStore } from "./store";

export const createMemoryVaultStore = (): VaultStore => {
  const sessions = new Map<string, VaultSessionRecord>();
  const nonces = new Set<string>();
  const counters = new Map<string, number>();

  return {
    async findLiveSession(id, now) {
      const s = sessions.get(id);
      if (!s || s.expiresAt.getTime() <= now.getTime()) return null;
      return { ...s, identities: s.identities.map((i) => ({ ...i })) };
    },
    async createSession(record) {
      sessions.set(record.id, { ...record, identities: [...record.identities] });
    },
    async addIdentity(id, addr, now, expiresAt) {
      const s = sessions.get(id);
      if (!s) return;
      if (!s.identities.some((i) => i.identityContractAddress === addr)) {
        s.identities.push({ identityContractAddress: addr, enrolledAt: now, lastUsedAt: now });
      }
      s.lastSeenAt = now;
      s.expiresAt = expiresAt;
    },
    async touch(id, addr, now, expiresAt) {
      const s = sessions.get(id);
      if (!s) return;
      s.lastSeenAt = now;
      s.expiresAt = expiresAt;
      const entry = addr ? s.identities.find((i) => i.identityContractAddress === addr) : undefined;
      if (entry) entry.lastUsedAt = now;
    },
    async removeIdentity(id, addr) {
      const s = sessions.get(id);
      if (!s) return { remaining: 0 };
      s.identities = s.identities.filter((i) => i.identityContractAddress !== addr);
      return { remaining: s.identities.length };
    },
    async deleteSession(id) {
      sessions.delete(id);
    },
    async removeIdentityEverywhere(addr) {
      let n = 0;
      for (const [id, s] of sessions) {
        const before = s.identities.length;
        s.identities = s.identities.filter((i) => i.identityContractAddress !== addr);
        if (s.identities.length !== before) n += 1;
        if (s.identities.length === 0) sessions.delete(id);
      }
      return n;
    },
    async consumeNonce(nonce) {
      if (nonces.has(nonce)) return false;
      nonces.add(nonce);
      return true;
    },
    async incrementCounter(key) {
      const next = (counters.get(key) ?? 0) + 1;
      counters.set(key, next);
      return next;
    },
  };
};
