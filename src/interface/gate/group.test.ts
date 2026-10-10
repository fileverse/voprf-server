import { describe, it, expect } from "vitest";
import { buildDocGroupResponse } from "./group";

// GET /doc/:docId/group is unauthenticated and read by every invitee open, so the
// shape is a wire contract: role lists in EXACT append order (clients rebuild the
// LeanIMT from them) plus the gate's currentEpoch, which lets an owner detect a
// blob anchored behind the gate (every invitee's unwrap fails at /release).
describe("buildDocGroupResponse", () => {
  const doc = {
    currentEpoch: 3,
    members: ["30", "10", "20"],
    bindings: [
      { idHash: "a", commitment: "10", role: "edit" },
      { idHash: "b", commitment: "20", role: "view" },
      { idHash: "c", commitment: "30", role: "edit" },
    ],
  };

  it("reports the gate's currentEpoch", () => {
    expect(buildDocGroupResponse(doc).currentEpoch).toBe(3);
  });

  it("keeps each role's members in doc.members append order", () => {
    const out = buildDocGroupResponse(doc);
    expect(out.edit.members).toEqual(["30", "10"]);
    expect(out.view.members).toEqual(["20"]);
    expect(out.comment.members).toEqual([]);
  });

  it("returns exactly the role groups plus currentEpoch", () => {
    expect(Object.keys(buildDocGroupResponse(doc)).sort()).toEqual(["comment", "currentEpoch", "edit", "view"]);
  });
});
