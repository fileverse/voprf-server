import { VaultRateCounter, VaultSession, VaultUcanNonce } from "./models";
import type { VaultSessionRecord, VaultStore } from "../../domain/vault/store";

const isDuplicateKey = (error: unknown): boolean =>
  typeof error === "object" && error !== null && (error as { code?: number }).code === 11000;

export const createMongoVaultStore = (): VaultStore => ({
  async findLiveSession(id, now) {
    // TTL sweeps lag ~60s, so the live window is enforced in the query.
    const doc = await VaultSession.findOne({ _id: id, expiresAt: { $gt: now } }).lean();
    if (!doc) return null;
    const record: VaultSessionRecord = {
      id: doc._id,
      identities: doc.identities,
      createdAt: doc.createdAt,
      lastSeenAt: doc.lastSeenAt,
      expiresAt: doc.expiresAt,
      userAgentHint: doc.userAgentHint,
    };
    return record;
  },
  async createSession(record) {
    await VaultSession.create({
      _id: record.id,
      identities: record.identities,
      createdAt: record.createdAt,
      lastSeenAt: record.lastSeenAt,
      expiresAt: record.expiresAt,
      userAgentHint: record.userAgentHint,
    });
  },
  async addIdentity(id, addr, now, expiresAt) {
    await VaultSession.updateOne(
      { _id: id, "identities.identityContractAddress": { $ne: addr } },
      { $push: { identities: { identityContractAddress: addr, enrolledAt: now, lastUsedAt: now } } }
    );
    await VaultSession.updateOne({ _id: id }, { $set: { lastSeenAt: now, expiresAt } });
  },
  async touch(id, addr, now, expiresAt) {
    if (addr) {
      await VaultSession.updateOne(
        { _id: id, "identities.identityContractAddress": addr },
        { $set: { lastSeenAt: now, expiresAt, "identities.$.lastUsedAt": now } }
      );
      return;
    }
    await VaultSession.updateOne({ _id: id }, { $set: { lastSeenAt: now, expiresAt } });
  },
  async removeIdentity(id, addr) {
    const doc = await VaultSession.findOneAndUpdate(
      { _id: id },
      { $pull: { identities: { identityContractAddress: addr } } },
      { new: true }
    ).lean();
    return { remaining: doc?.identities.length ?? 0 };
  },
  async deleteSession(id) {
    await VaultSession.deleteOne({ _id: id });
  },
  async removeIdentityEverywhere(addr) {
    // Scoped to addr on both passes so an unrelated session with zero identities is never touched.
    const deleted = await VaultSession.deleteMany({
      identities: { $size: 1 },
      "identities.identityContractAddress": addr,
    });
    const pulled = await VaultSession.updateMany(
      { "identities.identityContractAddress": addr },
      { $pull: { identities: { identityContractAddress: addr } } }
    );
    return deleted.deletedCount + pulled.modifiedCount;
  },
  async consumeNonce(nonce, addr, expiresAt) {
    try {
      await VaultUcanNonce.create({ nonce, identityContractAddress: addr, expiresAt });
      return true;
    } catch (error) {
      if (isDuplicateKey(error)) return false;
      throw error;
    }
  },
  async incrementCounter(key, expiresAt) {
    const doc = await VaultRateCounter.findOneAndUpdate(
      { key },
      { $inc: { count: 1 }, $setOnInsert: { expiresAt } },
      { upsert: true, new: true }
    ).lean();
    return doc?.count ?? 1;
  },
});
