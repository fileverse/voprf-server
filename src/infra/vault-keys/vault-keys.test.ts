import { describe, it, expect, beforeEach, vi } from "vitest";
import { randomBytes } from "crypto";
import { Oprf, VOPRFClient, VOPRFServer, Evaluation, EvaluationRequest } from "@cloudflare/voprf-ts";

const env = vi.hoisted(() => ({}) as Record<string, string | undefined>);
vi.mock("../../config", () => ({ config: env }));

import {
  deriveVaultKeyPair,
  getVaultKeyConfig,
  resetVaultKeysForTests,
  VAULT_SUITE,
} from "./index";

const A = "0x" + "a".repeat(40);
const B = "0x" + "b".repeat(40);

describe("vault keys", () => {
  beforeEach(() => {
    for (const k of Object.keys(env)) delete env[k];
    resetVaultKeysForTests();
  });

  it("is undefined when GATE_VAULT_KEY is unset", () => {
    expect(getVaultKeyConfig()).toBeUndefined();
  });

  it("throws on a key that is not 32 bytes", () => {
    env.GATE_VAULT_KEY = Buffer.alloc(31).toString("base64");
    expect(() => getVaultKeyConfig()).toThrow(/32 bytes/);
  });

  it("defaults to version 1 when GATE_VAULT_KEY_VERSION is an empty string", () => {
    env.GATE_VAULT_KEY = randomBytes(32).toString("base64");
    env.GATE_VAULT_KEY_VERSION = "";
    const cfg = getVaultKeyConfig();
    expect(cfg?.current.version).toBe(1);
  });

  it("parses current and previous versions", () => {
    env.GATE_VAULT_KEY = randomBytes(32).toString("base64");
    env.GATE_VAULT_KEY_VERSION = "3";
    env.GATE_VAULT_KEY_PREVIOUS = randomBytes(32).toString("base64");
    const cfg = getVaultKeyConfig();
    expect(cfg?.current.version).toBe(3);
    expect(cfg?.previous?.version).toBe(2);
  });

  it("derives deterministic, identity- and version-separated keys", async () => {
    const seed = randomBytes(32);
    const a1 = await deriveVaultKeyPair(seed, 1, A);
    const a1again = await deriveVaultKeyPair(seed, 1, A.toUpperCase().replace("0X", "0x"));
    const b1 = await deriveVaultKeyPair(seed, 1, B);
    const a2 = await deriveVaultKeyPair(seed, 2, A);
    expect(Buffer.from(a1.privateKey).equals(Buffer.from(a1again.privateKey))).toBe(true);
    expect(Buffer.from(a1.privateKey).equals(Buffer.from(b1.privateKey))).toBe(false);
    expect(Buffer.from(a1.privateKey).equals(Buffer.from(a2.privateKey))).toBe(false);
  });

  it("produces a key pair a VOPRF client can verify against", async () => {
    const { privateKey, publicKey } = await deriveVaultKeyPair(randomBytes(32), 1, A);
    const client = new VOPRFClient(VAULT_SUITE, publicKey);
    const server = new VOPRFServer(VAULT_SUITE, privateKey);
    const input = randomBytes(32);
    const [fin, req] = await client.blind([input]);
    const evaluation = await server.blindEvaluate(
      EvaluationRequest.deserialize(VAULT_SUITE, req.serialize())
    );
    const [out] = await client.finalize(fin, Evaluation.deserialize(VAULT_SUITE, evaluation.serialize()));
    expect(out.length).toBe(32);
    expect(VAULT_SUITE).toBe(Oprf.Suite.P256_SHA256);
  });
});
