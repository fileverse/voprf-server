import { Oprf, derivePrivateKey, generatePublicKey } from "@cloudflare/voprf-ts";
import { config } from "../../config";

export const VAULT_SUITE = Oprf.Suite.P256_SHA256;
export const VAULT_MODE = Oprf.Mode.VOPRF;

interface VaultKeyVersion {
  version: number;
  seed: Uint8Array;
}

interface VaultKeyConfig {
  current: VaultKeyVersion;
  previous?: VaultKeyVersion;
}

let cached: VaultKeyConfig | undefined;
let loaded = false;

const parseSeed = (name: string, raw: string): Uint8Array => {
  const seed = Buffer.from(raw, "base64");
  if (seed.length !== 32) {
    throw new Error(`vault keys: ${name} must decode to exactly 32 bytes`);
  }
  return new Uint8Array(seed);
};

// A malformed key throws at boot so a misconfigured deploy fails loudly; an unset
// key only disables /vault (503).
export const loadVaultKeys = (): void => {
  if (loaded) return;
  loaded = true;
  const raw = config.GATE_VAULT_KEY;
  if (!raw) {
    cached = undefined;
    return;
  }
  // `||`, not `??`: an empty string is a falsy-but-defined env var and must fall
  // back to 1 the same as unset, rather than becoming Number("") === 0.
  const version = Number(config.GATE_VAULT_KEY_VERSION || "1");
  if (!Number.isInteger(version) || version < 1) {
    throw new Error("vault keys: GATE_VAULT_KEY_VERSION must be a positive integer");
  }
  const current = { version, seed: parseSeed("GATE_VAULT_KEY", raw) };
  const previousRaw = config.GATE_VAULT_KEY_PREVIOUS;
  const previous =
    previousRaw && version > 1
      ? { version: version - 1, seed: parseSeed("GATE_VAULT_KEY_PREVIOUS", previousRaw) }
      : undefined;
  cached = { current, previous };
};

export const resetVaultKeysForTests = (): void => {
  loaded = false;
  cached = undefined;
};

export const getVaultKeyConfig = (): VaultKeyConfig | undefined => {
  loadVaultKeys();
  return cached;
};

export const deriveVaultKeyPair = async (
  seed: Uint8Array,
  version: number,
  identityContractAddress: string
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> => {
  const info = new TextEncoder().encode(
    `fv-vault-oprf/v${version}/${identityContractAddress.toLowerCase()}`
  );
  const privateKey = await derivePrivateKey(VAULT_MODE, VAULT_SUITE, seed, info);
  return { privateKey, publicKey: generatePublicKey(VAULT_SUITE, privateKey) };
};
