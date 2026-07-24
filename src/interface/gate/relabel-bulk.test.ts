import { describe, it, expect } from "vitest";
import { relabelBulkValidation } from "./relabel-bulk";

// /relabel-bulk is changeTier's bulk role switch. Unlike single /relabel it
// emits no eviction handles and no epoch bump, so accepting "edit" here would
// grant edit with no rotation — the schema must reject it.
describe("relabel-bulk validation", () => {
  const validate = (newRole: string) =>
    relabelBulkValidation.body.validate({
      docId: "doc-1",
      idHashes: ["h"],
      newRole,
      ownerUcan: "u",
    });

  it("rejects newRole:edit", () => {
    expect(validate("edit").error).toBeTruthy();
  });

  it("accepts newRole:comment", () => {
    expect(validate("comment").error).toBeFalsy();
  });

  it("accepts newRole:view", () => {
    expect(validate("view").error).toBeFalsy();
  });
});
