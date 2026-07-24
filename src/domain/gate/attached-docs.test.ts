import { describe, it, expect, vi, beforeEach } from "vitest";

const lean = vi.fn();
const find = vi.fn(() => ({ lean }));

vi.mock("../../infra/database/models", () => ({
  GateDoc: { find: (...a: unknown[]) => find(...a) },
}));

import { listEditAttachedDocIds } from "./attached-docs";

describe("listEditAttachedDocIds", () => {
  beforeEach(() => vi.clearAllMocks());

  it("queries gate_docs for the group at role=edit and returns docIds", async () => {
    lean.mockResolvedValue([{ docId: "doc-a" }, { docId: "doc-b" }]);
    const ids = await listEditAttachedDocIds("grp-7");
    expect(find).toHaveBeenCalledWith(
      { acceptedRoots: { $elemMatch: { groupRef: "grp-7", role: "edit" } } },
      { docId: 1 }
    );
    expect(ids).toEqual(["doc-a", "doc-b"]);
  });

  it("returns an empty array when no doc edit-attaches the group", async () => {
    lean.mockResolvedValue([]);
    expect(await listEditAttachedDocIds("grp-none")).toEqual([]);
  });
});

import { gateRouter } from "../../interface/gate";

describe("route registration", () => {
  it("mounts POST /group/:groupRef/attached-docs", () => {
    const routes = (gateRouter as unknown as { stack: Array<{ route?: { path: string; methods: Record<string, boolean> } }> }).stack
      .map((l) => l.route)
      .filter(Boolean) as Array<{ path: string; methods: Record<string, boolean> }>;
    const hit = routes.find((r) => r.path === "/group/:groupRef/attached-docs");
    expect(hit).toBeDefined();
    expect(hit!.methods.post).toBe(true);
  });
});
