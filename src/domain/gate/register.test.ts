import { describe, it, expect, vi, beforeEach } from "vitest";

const findOneLean = vi.fn();
const findOne = vi.fn(() => ({ lean: findOneLean }));
const create = vi.fn();
const findOneAndUpdateLean = vi.fn();
const findOneAndUpdate = vi.fn(() => ({ lean: findOneAndUpdateLean }));

vi.mock("../../infra/database/models", () => ({
  GateDoc: {
    findOne: (...a: unknown[]) => findOne(...a),
    create: (...a: unknown[]) => create(...a),
    findOneAndUpdate: (...a: unknown[]) => findOneAndUpdate(...a),
  },
}));

import { registerGateDoc } from "./register";

const anchor = { chainId: 100, portalAddress: "0xabc", fileId: 7 };
const docOwnRoots = [
  { groupRef: "doc-1", role: "view" },
  { groupRef: "doc-1", role: "comment" },
  { groupRef: "doc-1", role: "edit" },
];

describe("registerGateDoc", () => {
  beforeEach(() => vi.clearAllMocks());

  it("re-register preserves /attach-authored group entries (the group-editor kick regression)", async () => {
    findOneLean.mockResolvedValue({
      docId: "doc-1",
      anchorRef: anchor,
      acceptedRoots: [
        { groupRef: "doc-1", role: "view" },
        { groupRef: "grp-9", role: "edit" },
      ],
      currentEpoch: 3,
    });
    findOneAndUpdateLean.mockResolvedValue({ currentEpoch: 3 });

    const out = await registerGateDoc("doc-1", anchor, docOwnRoots);

    expect(out).toEqual({ kind: "ok", currentEpoch: 3 });
    expect(findOneAndUpdate).toHaveBeenCalledWith(
      { docId: "doc-1" },
      { $set: { acceptedRoots: [...docOwnRoots, { groupRef: "grp-9", role: "edit" }] } },
      { new: true }
    );
  });

  it("drops foreign groupRef entries from the caller's list (attach//detach are the sole authors)", async () => {
    findOneLean.mockResolvedValue({
      docId: "doc-1",
      anchorRef: anchor,
      acceptedRoots: [{ groupRef: "doc-1", role: "view" }],
      currentEpoch: 0,
    });
    findOneAndUpdateLean.mockResolvedValue({ currentEpoch: 0 });

    await registerGateDoc("doc-1", anchor, [
      ...docOwnRoots,
      { groupRef: "grp-injected", role: "edit" },
    ]);

    expect(findOneAndUpdate).toHaveBeenCalledWith(
      { docId: "doc-1" },
      { $set: { acceptedRoots: docOwnRoots } },
      { new: true }
    );
  });

  it("creates at epoch 0 with only doc-own roots", async () => {
    findOneLean.mockResolvedValue(null);
    create.mockResolvedValue(undefined);

    const out = await registerGateDoc("doc-1", anchor, [
      ...docOwnRoots,
      { groupRef: "grp-x", role: "edit" },
    ]);

    expect(out).toEqual({ kind: "ok", currentEpoch: 0 });
    expect(create).toHaveBeenCalledWith({
      docId: "doc-1",
      anchorRef: anchor,
      acceptedRoots: docOwnRoots,
      currentEpoch: 0,
      members: [],
      bindings: [],
    });
  });

  it("rejects a different anchor (first-writer-wins)", async () => {
    findOneLean.mockResolvedValue({
      docId: "doc-1",
      anchorRef: { ...anchor, fileId: 99 },
      acceptedRoots: docOwnRoots,
      currentEpoch: 1,
    });

    expect(await registerGateDoc("doc-1", anchor, docOwnRoots)).toEqual({
      kind: "anchor-mismatch",
    });
    expect(findOneAndUpdate).not.toHaveBeenCalled();
  });
});
