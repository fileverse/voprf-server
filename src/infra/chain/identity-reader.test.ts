import { describe, it, expect, vi } from "vitest";
import {
  createPublicClient,
  custom,
  encodeFunctionResult,
  RpcRequestError,
  type PublicClient,
} from "viem";
import { IDENTITY_MODULE_ABI } from "./identity-module-abi";

// getIdentitySigningDidStrict must tell a real "no module here" (empty data, an
// on-chain revert) apart from a struggling RPC provider (transport failure, or an
// internal-error response), which must keep propagating rather than resolve to null.
// These drive real JSON-RPC error shapes through viem's own readContract/getContractError
// pipeline via a fake `custom` transport, no network involved, rather than hand-building
// viem's internal error classes and hoping the shape matches what viem itself produces.

let client: PublicClient;
vi.mock("./viem-client", () => ({
  getPublicClient: () => client,
}));

import { getIdentitySigningDidStrict } from "./identity-reader";

const ADDR = "0x" + "a".repeat(40);

const clientWithRequest = (request: (args: unknown) => Promise<unknown>): PublicClient =>
  createPublicClient({ transport: custom({ request }, { retryCount: 0 }) });

const encodedDetails = (signingDid: string): `0x${string}` =>
  encodeFunctionResult({
    abi: IDENTITY_MODULE_ABI,
    functionName: "getIdentityModulePublicDetails",
    result: {
      salt: 0n,
      signingDid,
      accountPublicKey: "0x",
      agentAddress: "0x0000000000000000000000000000000000000000",
    },
  });

const rpcError = (error: { code: number; message: string; data?: string }) =>
  new RpcRequestError({ body: {}, error, url: "http://fake" });

describe("getIdentitySigningDidStrict", () => {
  it("returns the signingDid on a successful read", async () => {
    client = clientWithRequest(async () => encodedDetails("did:key:zSomeDid"));
    await expect(getIdentitySigningDidStrict(ADDR)).resolves.toBe("did:key:zSomeDid");
  });

  it("returns null when signingDid is empty", async () => {
    client = clientWithRequest(async () => encodedDetails(""));
    await expect(getIdentitySigningDidStrict(ADDR)).resolves.toBeNull();
  });

  it("returns null when the read comes back with zero data (no contract at that address)", async () => {
    client = clientWithRequest(async () => "0x");
    await expect(getIdentitySigningDidStrict(ADDR)).resolves.toBeNull();
  });

  it("returns null on a genuine on-chain revert (JSON-RPC code 3, revert data)", async () => {
    client = clientWithRequest(async () => {
      throw rpcError({ code: 3, message: "execution reverted", data: "0x08c379a0" + "0".repeat(56) });
    });
    await expect(getIdentitySigningDidStrict(ADDR)).resolves.toBeNull();
  });

  it("returns null on a genuine on-chain revert reported as -32000 with revert data", async () => {
    client = clientWithRequest(async () => {
      throw rpcError({ code: -32000, message: "execution reverted", data: "0x08c379a0" + "0".repeat(56) });
    });
    await expect(getIdentitySigningDidStrict(ADDR)).resolves.toBeNull();
  });

  it("propagates a -32603 internal RPC error instead of treating it as no module", async () => {
    client = clientWithRequest(async () => {
      throw rpcError({ code: -32603, message: "Internal error" });
    });
    await expect(getIdentitySigningDidStrict(ADDR)).rejects.toThrow();
  });

  it("propagates a raw transport failure (no RPC error code at all)", async () => {
    client = clientWithRequest(async () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:1");
    });
    await expect(getIdentitySigningDidStrict(ADDR)).rejects.toThrow();
  });
});
