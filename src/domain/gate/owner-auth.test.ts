import { describe, it, expect, vi, beforeEach } from "vitest";
import type { GateDocRecord } from "../../infra/database/models";

const verifyIdentityUcan = vi.fn();
vi.mock("./identity-ucan", () => ({
  verifyIdentityUcan: (...a: unknown[]) => verifyIdentityUcan(...a),
}));

import { assertDocOwnerIdentity } from "./owner-auth";
import { GateErrorCode } from "../../infra/gate-errors";

const OWNER_CONTRACT = "0xabc0000000000000000000000000000000000001";

function doc(overrides: Partial<GateDocRecord> = {}): GateDocRecord {
  return {
    docId: "doc-1",
    anchorRef: { chainId: 100, portalAddress: "0xportal", fileId: 7 },
    acceptedRoots: [],
    currentEpoch: 0,
    members: [],
    bindings: [],
    revokedIdHashes: [],
    ...overrides,
  };
}

describe("assertDocOwnerIdentity", () => {
  beforeEach(() => vi.clearAllMocks());

  it("passes without checking identity for a legacy doc (no ownerIdentityContract)", async () => {
    await expect(assertDocOwnerIdentity("any-ucan", doc())).resolves.toBeUndefined();
    expect(verifyIdentityUcan).not.toHaveBeenCalled();
  });

  it("passes when the identity UCAN resolves to the bound creator contract", async () => {
    verifyIdentityUcan.mockResolvedValue({ identityContractAddress: OWNER_CONTRACT });
    await expect(
      assertDocOwnerIdentity("owner-ucan", doc({ ownerIdentityContract: OWNER_CONTRACT }))
    ).resolves.toBeUndefined();
  });

  it("rejects 403 when the identity UCAN resolves to a different contract", async () => {
    verifyIdentityUcan.mockResolvedValue({ identityContractAddress: "0xdifferent00000000000000000000000000000009" });
    await expect(
      assertDocOwnerIdentity("collaborator-ucan", doc({ ownerIdentityContract: OWNER_CONTRACT }))
    ).rejects.toMatchObject({ code: 403, message: GateErrorCode.NOT_DOC_OWNER });
  });

  it("rejects 403 when a bound doc receives no identity proof (does not call verify)", async () => {
    await expect(
      assertDocOwnerIdentity(undefined, doc({ ownerIdentityContract: OWNER_CONTRACT }))
    ).rejects.toMatchObject({ code: 403, message: GateErrorCode.NOT_DOC_OWNER });
    expect(verifyIdentityUcan).not.toHaveBeenCalled();
  });

  it("rejects 403 when the identity proof fails to verify (returns null)", async () => {
    verifyIdentityUcan.mockResolvedValue(null);
    await expect(
      assertDocOwnerIdentity("bad-ucan", doc({ ownerIdentityContract: OWNER_CONTRACT }))
    ).rejects.toMatchObject({ code: 403, message: GateErrorCode.NOT_DOC_OWNER });
  });
});
