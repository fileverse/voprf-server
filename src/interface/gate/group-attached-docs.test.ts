import type { Request, Response } from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

const gate = vi.hoisted(() => ({
  assertGroupOwnerAuthorized: vi.fn(),
  getGateGroup: vi.fn(),
  listEditAttachedDocIds: vi.fn(),
  listGroupAttachments: vi.fn(),
}));
vi.mock("../../domain/gate", () => gate);

import groupAttachedDocs from "./group-attached-docs";

describe("group attachment discovery", () => {
  const anchorRef = { chainId: 1, portalAddress: "portal", fileId: 0 };
  const handle = groupAttachedDocs[1] as (req: Request, res: Response) => Promise<void>;
  const json = vi.fn();
  const request = (scope?: "all") =>
    ({ params: { groupRef: "design" }, body: { ownerUcan: "token", scope } }) as unknown as Request;
  const response = { json } as unknown as Response;

  beforeEach(() => {
    vi.resetAllMocks();
    gate.getGateGroup.mockResolvedValue({ anchorRef });
  });

  it("preserves the Editor-only response for existing callers", async () => {
    gate.listEditAttachedDocIds.mockResolvedValue(["doc-edit"]);
    await handle(request(), response);
    expect(json).toHaveBeenCalledWith({ docIds: ["doc-edit"] });
    expect(gate.listGroupAttachments).not.toHaveBeenCalled();
  });

  it("authorizes and returns role-aware results for the opt-in scope", async () => {
    const attachments = [{ gateId: "folder", role: "comment" }];
    gate.listGroupAttachments.mockResolvedValue(attachments);
    await handle(request("all"), response);
    expect(gate.assertGroupOwnerAuthorized).toHaveBeenCalledWith("token", "design", anchorRef);
    expect(json).toHaveBeenCalledWith({ attachments });
  });

  it("does not query attachments when the group-owner proof fails", async () => {
    gate.assertGroupOwnerAuthorized.mockRejectedValue(new Error("forbidden"));
    await expect(handle(request("all"), response)).rejects.toThrow("forbidden");
    expect(gate.listGroupAttachments).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });
});
