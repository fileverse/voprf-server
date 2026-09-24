export interface VaultSessionIdentity {
  identityContractAddress: string;
  enrolledAt: Date;
  lastUsedAt: Date;
}

export interface VaultSessionRecord {
  id: string; // sha256(cookie token) hex
  identities: VaultSessionIdentity[];
  createdAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
  userAgentHint?: string;
}

export interface VaultStore {
  findLiveSession(id: string, now: Date): Promise<VaultSessionRecord | null>;
  createSession(record: VaultSessionRecord): Promise<void>;
  addIdentity(id: string, identityContractAddress: string, now: Date, expiresAt: Date): Promise<void>;
  touch(id: string, identityContractAddress: string | null, now: Date, expiresAt: Date): Promise<void>;
  removeIdentity(id: string, identityContractAddress: string): Promise<{ remaining: number }>;
  deleteSession(id: string): Promise<void>;
  removeIdentityEverywhere(identityContractAddress: string): Promise<number>;
  /** False when the nonce was already consumed. */
  consumeNonce(nonce: string, identityContractAddress: string, expiresAt: Date): Promise<boolean>;
  /** Atomically increments and returns the new count. */
  incrementCounter(key: string, expiresAt: Date): Promise<number>;
}

let store: VaultStore | undefined;

export const setVaultStore = (next: VaultStore): void => {
  store = next;
};

export const getVaultStore = (): VaultStore => {
  if (!store) throw new Error("vault: store not installed");
  return store;
};

// True once setVaultStore has run.
export const hasVaultStore = (): boolean => store !== undefined;

export const resetVaultStoreForTests = (): void => {
  store = undefined;
};
