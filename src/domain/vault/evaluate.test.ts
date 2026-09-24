import { describe, it, expect, beforeEach, vi } from "vitest";
import { randomBytes } from "crypto";
import { fromUint8Array, toUint8Array } from "js-base64";
import { VOPRFClient, Evaluation } from "@cloudflare/voprf-ts";

const env = vi.hoisted(() => ({}) as Record<string, string | undefined>);
vi.mock("../../config", () => ({ config: env }));

import { resetVaultKeysForTests, VAULT_SUITE } from "../../infra/vault-keys";
import { evaluateForIdentity, getVaultPublicKey } from "./evaluate";

const A = "0x" + "a".repeat(40);

const roundTrip = async (publicKey: string, version: number, input: Uint8Array) => {
  const client = new VOPRFClient(VAULT_SUITE, toUint8Array(publicKey));
  const [fin, req] = await client.blind([input]);
  const res = await evaluateForIdentity(A, fromUint8Array(req.serialize()), version);
  const [out] = await client.finalize(fin, Evaluation.deserialize(VAULT_SUITE, toUint8Array(res.evaluation)));
  return { out: Buffer.from(out).toString("hex"), res };
};

describe("vault evaluation", () => {
  beforeEach(() => {
    for (const k of Object.keys(env)) delete env[k];
    resetVaultKeysForTests();
  });

  it("returns 503 without a key", async () => {
    await expect(getVaultPublicKey(A)).rejects.toMatchObject({ code: 503 });
  });

  it("is deterministic per identity and verifiable", async () => {
    env.GATE_VAULT_KEY = randomBytes(32).toString("base64");
    const { publicKey, keyVersion } = await getVaultPublicKey(A);
    const input = randomBytes(32);
    const first = await roundTrip(publicKey, keyVersion, input);
    const second = await roundTrip(publicKey, keyVersion, input);
    expect(first.out).toBe(second.out);
    expect(first.res.currentKeyVersion).toBe(1);
  });

  it("serves the previous version during rotation and refuses older", async () => {
    const oldSeed = randomBytes(32).toString("base64");
    env.GATE_VAULT_KEY = oldSeed;
    resetVaultKeysForTests();
    const v1 = await getVaultPublicKey(A);
    const input = randomBytes(32);
    const before = await roundTrip(v1.publicKey, 1, input);

    env.GATE_VAULT_KEY = randomBytes(32).toString("base64");
    env.GATE_VAULT_KEY_VERSION = "2";
    env.GATE_VAULT_KEY_PREVIOUS = oldSeed;
    resetVaultKeysForTests();
    const stillV1 = await roundTrip(v1.publicKey, 1, input);
    expect(stillV1.out).toBe(before.out);
    expect(stillV1.res.currentKeyVersion).toBe(2);

    delete env.GATE_VAULT_KEY_PREVIOUS;
    env.GATE_VAULT_KEY_VERSION = "3";
    resetVaultKeysForTests();
    await expect(roundTrip(v1.publicKey, 1, input)).rejects.toMatchObject({ code: 409 });
  });

  it("rejects a malformed evaluation request with 400", async () => {
    env.GATE_VAULT_KEY = randomBytes(32).toString("base64");
    await expect(evaluateForIdentity(A, "not-base64-!!", 1)).rejects.toMatchObject({ code: 400 });
  });
});
