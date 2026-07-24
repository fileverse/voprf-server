import { describe, it, expect, vi, beforeEach } from "vitest";
import * as ucans from "@ucans/ucans";

const getIdentitySigningDid = vi.fn();
const getGateSigningDid = vi.fn();

vi.mock("../../infra/chain/identity-reader", () => ({
  getIdentitySigningDid: (...a: unknown[]) => getIdentitySigningDid(...a),
}));
vi.mock("../../infra/gate-keys", () => ({
  getGateSigningDid: (...a: unknown[]) => getGateSigningDid(...a),
}));

import { verifyIdentityUcan } from "./identity-ucan";

const GATE_DID = "did:key:z6MkgateAudienceForTest0000000000000000000000";
const IDENTITY_CONTRACT = "0xAbC0000000000000000000000000000000000001";

// A self-signed identity UCAN: issued by the identity's signing key, audienced to the
// gate, carrying identityContractAddress in facts + capability. verifyIdentityUcan resolves
// the on-chain signingDid and requires the token be rooted there.
async function mintIdentityUcan(args: {
  issuer: ucans.EdKeypair;
  audience: string;
  addressInFacts: string;
  addressInCap: string;
}): Promise<string> {
  const built = await ucans.build({
    issuer: args.issuer,
    audience: args.audience,
    capabilities: [
      {
        with: { scheme: "identity", hierPart: args.addressInCap.toLowerCase() },
        can: { namespace: "identity", segments: ["PROVE"] },
      },
    ],
    facts: [{ identityContractAddress: args.addressInFacts }],
    lifetimeInSeconds: 300,
  });
  return ucans.encode(built);
}

describe("verifyIdentityUcan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getGateSigningDid.mockReturnValue(GATE_DID);
  });

  it("returns the lowercased identityContractAddress for a token rooted at the on-chain signingDid", async () => {
    const idKey = await ucans.EdKeypair.create();
    getIdentitySigningDid.mockResolvedValue(idKey.did());
    const token = await mintIdentityUcan({
      issuer: idKey,
      audience: GATE_DID,
      addressInFacts: IDENTITY_CONTRACT,
      addressInCap: IDENTITY_CONTRACT,
    });

    const result = await verifyIdentityUcan(token);
    expect(result).toEqual({ identityContractAddress: IDENTITY_CONTRACT.toLowerCase() });
    expect(getIdentitySigningDid).toHaveBeenCalledWith(IDENTITY_CONTRACT.toLowerCase());
  });

  it("returns null when the token is not rooted at the on-chain signingDid (forged identity)", async () => {
    const idKey = await ucans.EdKeypair.create();
    const attackerKey = await ucans.EdKeypair.create();
    // The chain says the identity's signingDid is idKey, but the token was signed by attackerKey.
    getIdentitySigningDid.mockResolvedValue(idKey.did());
    const token = await mintIdentityUcan({
      issuer: attackerKey,
      audience: GATE_DID,
      addressInFacts: IDENTITY_CONTRACT,
      addressInCap: IDENTITY_CONTRACT,
    });

    expect(await verifyIdentityUcan(token)).toBeNull();
  });

  it("returns null for a token audienced to a different service (no cross-service replay)", async () => {
    const idKey = await ucans.EdKeypair.create();
    getIdentitySigningDid.mockResolvedValue(idKey.did());
    const token = await mintIdentityUcan({
      issuer: idKey,
      audience: "did:key:z6MkSomeOtherServiceAudience00000000000000000",
      addressInFacts: IDENTITY_CONTRACT,
      addressInCap: IDENTITY_CONTRACT,
    });

    expect(await verifyIdentityUcan(token)).toBeNull();
  });

  it("returns null when the capability scope does not match the facts address", async () => {
    const idKey = await ucans.EdKeypair.create();
    getIdentitySigningDid.mockResolvedValue(idKey.did());
    const token = await mintIdentityUcan({
      issuer: idKey,
      audience: GATE_DID,
      addressInFacts: IDENTITY_CONTRACT,
      addressInCap: "0xdead000000000000000000000000000000000000",
    });

    expect(await verifyIdentityUcan(token)).toBeNull();
  });

  it("returns null when the identity contract has no on-chain signingDid", async () => {
    const idKey = await ucans.EdKeypair.create();
    getIdentitySigningDid.mockResolvedValue(null);
    const token = await mintIdentityUcan({
      issuer: idKey,
      audience: GATE_DID,
      addressInFacts: IDENTITY_CONTRACT,
      addressInCap: IDENTITY_CONTRACT,
    });

    expect(await verifyIdentityUcan(token)).toBeNull();
  });

  it("returns null when the gate has no signing DID configured", async () => {
    getGateSigningDid.mockReturnValue(undefined);
    const idKey = await ucans.EdKeypair.create();
    getIdentitySigningDid.mockResolvedValue(idKey.did());
    const token = await mintIdentityUcan({
      issuer: idKey,
      audience: GATE_DID,
      addressInFacts: IDENTITY_CONTRACT,
      addressInCap: IDENTITY_CONTRACT,
    });

    expect(await verifyIdentityUcan(token)).toBeNull();
  });

  it("returns null when no identityContractAddress is present in facts", async () => {
    const idKey = await ucans.EdKeypair.create();
    getIdentitySigningDid.mockResolvedValue(idKey.did());
    const built = await ucans.build({
      issuer: idKey,
      audience: GATE_DID,
      capabilities: [
        {
          with: { scheme: "identity", hierPart: "0x0" },
          can: { namespace: "identity", segments: ["PROVE"] },
        },
      ],
      lifetimeInSeconds: 300,
    });
    expect(await verifyIdentityUcan(ucans.encode(built))).toBeNull();
  });
});
