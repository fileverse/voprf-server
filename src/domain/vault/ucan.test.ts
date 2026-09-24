import { describe, it, expect, vi, beforeEach } from "vitest";
import * as ucans from "@ucans/ucans";
import { randomBytes } from "crypto";
import { setVaultStore } from "./store";
import { createMemoryVaultStore } from "./memory-store";

const getIdentitySigningDidStrict = vi.fn();
const getGateSigningDid = vi.fn();
vi.mock("../../infra/chain/identity-reader", () => ({
  getIdentitySigningDidStrict: (...a: unknown[]) => getIdentitySigningDidStrict(...a),
}));
vi.mock("../../infra/gate-keys", () => ({
  getGateSigningDid: (...a: unknown[]) => getGateSigningDid(...a),
}));

import { verifyVaultUcan } from "./ucan";

const ADDR = "0x" + "c".repeat(40);

interface MintOpts {
  segment?: string;
  canSegments?: string[];
  canSuperuser?: boolean;
  audience?: string;
  hierPart?: string;
  factAddress?: string;
  lifetime?: number;
  notBeforeOffset?: number;
  nonce?: boolean;
  jti?: string;
  proofs?: string[];
  issuer?: ucans.EdKeypair;
}

let identityKey: ucans.EdKeypair;
let gateKey: ucans.EdKeypair;

const mint = async (o: MintOpts = {}) => {
  const now = Math.floor(Date.now() / 1000);
  const nbf = now + (o.notBeforeOffset ?? 0);
  const can: ucans.Ability = o.canSuperuser
    ? "*"
    : { namespace: "identity", segments: o.canSegments ?? [o.segment ?? "VAULT"] };
  const token = await ucans.build({
    issuer: o.issuer ?? identityKey,
    audience: o.audience ?? gateKey.did(),
    notBefore: nbf,
    expiration: nbf + (o.lifetime ?? 300),
    capabilities: [
      {
        with: { scheme: "identity", hierPart: o.hierPart ?? ADDR },
        can,
      },
    ],
    facts: [
      o.nonce === false
        ? { identityContractAddress: o.factAddress ?? ADDR }
        : { identityContractAddress: o.factAddress ?? ADDR, jti: o.jti ?? randomBytes(32).toString("base64url") },
    ],
    proofs: o.proofs,
  });
  return ucans.encode(token);
};

// Same bytes as ADDR, alternating case on every letter (ADDR is all "c").
const MIXED_CASE_ADDR = "0x" + "cC".repeat(20);

const status = async (p: Promise<unknown>) => {
  try {
    await p;
    return 200;
  } catch (e) {
    return (e as { code?: number }).code;
  }
};

describe("verifyVaultUcan", () => {
  beforeEach(async () => {
    identityKey = await ucans.EdKeypair.create();
    gateKey = await ucans.EdKeypair.create();
    getGateSigningDid.mockReturnValue(gateKey.did());
    getIdentitySigningDidStrict.mockResolvedValue(identityKey.did());
    setVaultStore(createMemoryVaultStore());
  });

  it("accepts a well-formed VAULT token", async () => {
    await expect(verifyVaultUcan(await mint())).resolves.toEqual({ identityContractAddress: ADDR });
  });

  it("rejects a PROVE token (segment separation)", async () => {
    expect(await status(verifyVaultUcan(await mint({ segment: "PROVE" })))).toBe(401);
  });

  it("rejects the wrong audience", async () => {
    const other = await ucans.EdKeypair.create();
    expect(await status(verifyVaultUcan(await mint({ audience: other.did() })))).toBe(401);
  });

  it("rejects a capability for another identity", async () => {
    expect(await status(verifyVaultUcan(await mint({ hierPart: "0x" + "d".repeat(40) })))).toBe(401);
  });

  it("rejects an issuer that is not the on-chain signing DID", async () => {
    const forger = await ucans.EdKeypair.create();
    expect(await status(verifyVaultUcan(await mint({ issuer: forger })))).toBe(401);
  });

  it("rejects a lifetime above 600s", async () => {
    expect(await status(verifyVaultUcan(await mint({ lifetime: 601 })))).toBe(401);
  });

  it("tolerates a client clock two hours ahead", async () => {
    await expect(verifyVaultUcan(await mint({ notBeforeOffset: 7200 }))).resolves.toBeTruthy();
  });

  it("rejects a token minted more than a day away from gate time", async () => {
    expect(await status(verifyVaultUcan(await mint({ notBeforeOffset: -90000 })))).toBe(401);
  });

  it("rejects a token without a jti", async () => {
    expect(await status(verifyVaultUcan(await mint({ nonce: false })))).toBe(401);
  });

  it("rejects a replayed token", async () => {
    const token = await mint();
    await verifyVaultUcan(token);
    expect(await status(verifyVaultUcan(token))).toBe(401);
  });

  it("returns 503 when the gate DID is not configured", async () => {
    getGateSigningDid.mockReturnValue(undefined);
    expect(await status(verifyVaultUcan(await mint()))).toBe(503);
  });

  it("propagates an RPC failure instead of rejecting as invalid", async () => {
    const rpc = new Error("rpc down");
    getIdentitySigningDidStrict.mockRejectedValue(rpc);
    await expect(verifyVaultUcan(await mint())).rejects.toBe(rpc);
  });

  it("rejects a token that carries a proof (no delegation allowed)", async () => {
    expect(await status(verifyVaultUcan(await mint({ proofs: ["not.a.real.proof"] })))).toBe(401);
  });

  it("rejects a superuser (*) capability", async () => {
    expect(await status(verifyVaultUcan(await mint({ canSuperuser: true })))).toBe(401);
  });

  it("rejects a multi-segment ability", async () => {
    expect(await status(verifyVaultUcan(await mint({ canSegments: ["VAULT", "EXTRA"] })))).toBe(401);
  });

  it("rejects a fact address that does not match the capability's hierPart", async () => {
    expect(
      await status(verifyVaultUcan(await mint({ factAddress: "0x" + "e".repeat(40) })))
    ).toBe(401);
  });

  it("accepts a checksummed/mixed-case address and returns it lowercased", async () => {
    await expect(
      verifyVaultUcan(await mint({ hierPart: MIXED_CASE_ADDR, factAddress: MIXED_CASE_ADDR }))
    ).resolves.toEqual({ identityContractAddress: ADDR });
  });

  it("rejects a jti shorter than 22 characters", async () => {
    expect(await status(verifyVaultUcan(await mint({ jti: "tooshort" })))).toBe(401);
  });

  it("rejects a token whose exp does not exceed nbf", async () => {
    expect(await status(verifyVaultUcan(await mint({ lifetime: 0 })))).toBe(401);
  });
});
