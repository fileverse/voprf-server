// Signature-path edit-admission UCAN, rooted at the gate signing DID and audienced to the
// collab server. facts carry the per-actor editHandle plus the epoch at which it was minted;
// the collab server rejects a UCAN whose epoch is below the doc's minEditEpoch offline (no
// runtime gate call). See docs/architecture/gp-semaphore.md.
import * as ucans from "@ucans/ucans";
import { getGateSigningKeypair } from "../../infra/gate-keys";
import { config } from "../../config";

export const mintEditUcan = async (args: {
  docId: string;
  editHandle: string;
  epoch: number;
}): Promise<string | undefined> => {
  const keypair = getGateSigningKeypair();
  const audience = config.COLLAB_SERVER_DID;
  if (!keypair || !audience) return undefined;

  const built = await ucans.build({
    issuer: keypair,
    audience,
    capabilities: [
      {
        with: { scheme: "collab", hierPart: args.docId },
        can: { namespace: "collab", segments: ["EDIT"] },
      },
    ],
    facts: [{ docId: args.docId, editHandle: args.editHandle, epoch: args.epoch }],
    lifetimeInSeconds: 60 * 60 * 24 * 7,
  });
  return ucans.encode(built);
};
