import { describe, it, expect, vi, beforeEach } from "vitest";
import * as ucans from "@ucans/ucans";

const signingKeypair = await ucans.EdKeypair.create();

vi.mock("../../infra/gate-keys", () => ({
  getGateSigningKeypair: vi.fn(() => signingKeypair),
}));
vi.mock("../../config", () => ({
  config: { COLLAB_SERVER_DID: "did:key:zCollabAudience" },
}));

import { mintEditUcan } from "./mint-edit-ucan";
import { getGateSigningKeypair } from "../../infra/gate-keys";

describe("mintEditUcan", () => {
  beforeEach(() => vi.clearAllMocks());

  it("embeds docId, editHandle AND epoch in the first fact", async () => {
    const token = await mintEditUcan({ docId: "doc-1", editHandle: "h-9", epoch: 4 });
    expect(token).toBeTypeOf("string");
    const parsed = ucans.parse(token as string);
    expect(parsed.payload.fct?.[0]).toEqual({ docId: "doc-1", editHandle: "h-9", epoch: 4 });
  });

  it("returns undefined when the signing keypair is not configured", async () => {
    (getGateSigningKeypair as ReturnType<typeof vi.fn>).mockReturnValueOnce(undefined);
    const token = await mintEditUcan({ docId: "doc-1", editHandle: "h-9", epoch: 4 });
    expect(token).toBeUndefined();
  });
});
