// POST /gate/release. LOAD-BEARING pipeline (do NOT reorder): shape → scope →
// nonce match+consume (BEFORE the verify outcome) → exact-current-root (409) →
// verifyProof (403) → derive at the gate's OWN currentEpoch.
// proof is intentionally Joi.any: parseProofShape owns ALL proof validation (incl.
// a missing/non-object proof), so its 400 messages and their position are preserved.
import { Request, Response } from "express";
import * as ucans from "@ucans/ucans";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { config } from "../../config";
import { getGateMasterKey, getGateSigningKeypair } from "../../infra/gate-keys";
import {
  assertProofScope,
  assertProofValid,
  assertRootInSet,
  consumeGateNonce,
  deriveGateShare,
  deriveEditHandle,
  getGateDoc,
  isEditMember,
  listLiveNonces,
  matchNonceByEncodedMessage,
  parseProofShape,
  resolveAcceptedRoots,
  verifyEditSignatureAndDeriveCommitment,
} from "../../domain/gate";
import type { EddsaSignature } from "../../domain/gate";
import { docIdField } from "./validation";

const releaseValidation = {
  body: Joi.object({
    docId: docIdField(),
    proof: Joi.any(),
    // Optional signature-identified edit path — additive alongside `proof`.
    nonce: Joi.string(),
    publicKey: Joi.array().items(Joi.string()).length(2),
    signature: Joi.object({
      R8: Joi.array().items(Joi.string()).length(2).required(),
      S: Joi.string().required(),
    }),
  }),
};

async function releaseGateShare(req: Request, res: Response): Promise<void> {
  const { docId, proof, nonce, publicKey, signature } = req.body as {
    docId: string;
    proof: unknown;
    nonce?: string;
    publicKey?: [string, string];
    signature?: EddsaSignature;
  };

  const masterKey = getGateMasterKey();
  if (!masterKey) return throwError({ code: 503, message: GateErrorCode.MASTER_KEY_NOT_CONFIGURED });

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

  // Signature-identified edit path: commitment-identified, no Semaphore proof.
  if (signature && publicKey && nonce) {
    const liveNonces = await listLiveNonces(docId);
    if (!liveNonces.includes(nonce) || !(await consumeGateNonce(docId, nonce))) {
      return throwError({ code: 403, message: GateErrorCode.NONCE_NOT_LIVE });
    }
    const commitment = verifyEditSignatureAndDeriveCommitment(docId, nonce, publicKey, signature);
    if (!commitment) return throwError({ code: 403, message: GateErrorCode.INVALID_PROOF });
    if (!(await isEditMember(doc, commitment))) {
      return throwError({ code: 403, message: GateErrorCode.INVALID_PROOF });
    }

    const shares = {
      view: deriveGateShare(masterKey, doc.anchorRef, doc.currentEpoch, "view"),
      comment: deriveGateShare(masterKey, doc.anchorRef, doc.currentEpoch, "comment"),
      edit: deriveGateShare(masterKey, doc.anchorRef, doc.currentEpoch, "edit"),
    };
    const editHandle = deriveEditHandle(commitment, docId);

    // Mirrors the legacy edit UCAN mint below: same graceful degrade, same 7-day lifetime.
    let editUcan: string | undefined;
    const keypair = getGateSigningKeypair();
    const audience = config.COLLAB_SERVER_DID;
    if (keypair && audience) {
      const built = await ucans.build({
        issuer: keypair,
        audience,
        capabilities: [
          {
            with: { scheme: "collab", hierPart: docId },
            can: { namespace: "collab", segments: ["EDIT"] },
          },
        ],
        facts: [{ docId, editHandle }],
        lifetimeInSeconds: 60 * 60 * 24 * 7,
      });
      editUcan = ucans.encode(built);
    }

    res.json({ shares, ...(editUcan ? { editUcan, editHandle } : {}) });
    return;
  }

  const shape = parseProofShape(proof);
  assertProofScope(shape, docId);

  // Single-use nonce, consumed BEFORE the verify outcome — a failed proof burns its challenge (anti-grinding).
  const liveNonces = await listLiveNonces(docId);
  const matched = matchNonceByEncodedMessage(shape.message, liveNonces);
  if (!matched || !(await consumeGateNonce(docId, matched))) {
    return throwError({ code: 403, message: GateErrorCode.NONCE_NOT_LIVE });
  }

  // Additive implicit group + per-role roots: accept the proof if its root is in the
  // union of role-filtered roots; the matched entry's role decides the share bundle.
  const acceptedEntries = await resolveAcceptedRoots(doc);
  assertRootInSet(shape, acceptedEntries.map((e) => e.root));
  await assertProofValid(shape);

  // Which accepted entry did the proof match? (assertRootInSet already guaranteed one.)
  const matchedEntry = acceptedEntries.find((e) => e.root === shape.merkleTreeRoot);
  if (!matchedEntry) return throwError({ code: 409, message: GateErrorCode.STALE_GROUP_ROOT });

  // .lean() skips the schema default, so pre-existing docs can read back as undefined —
  // coalesce once here so it's never undefined in the UCAN fact or the response.
  const editGrantEpoch = doc.editGrantEpoch ?? 0;

  // Bundle by hierarchy (edit ⊇ comment ⊇ view), derived at the gate's OWN currentEpoch.
  const shares: { view: string; comment?: string; edit?: string } = {
    view: deriveGateShare(masterKey, doc.anchorRef, doc.currentEpoch, "view"),
  };
  if (matchedEntry.role === "comment" || matchedEntry.role === "edit") {
    shares.comment = deriveGateShare(masterKey, doc.anchorRef, doc.currentEpoch, "comment");
  }

  // Edit match: also derive the edit share and mint the edit-admission UCAN. The UCAN is
  // the collab-server's write-admission proof; it carries ONLY (docId, editGrantEpoch, nullifier)
  // — never an idHash/commitment — so the gate's zero-knowledge property is preserved. A
  // missing signing key or collab DID degrades gracefully (share still returned, UCAN absent).
  let editUcan: string | undefined;
  if (matchedEntry.role === "edit") {
    shares.edit = deriveGateShare(masterKey, doc.anchorRef, doc.currentEpoch, "edit");
    const keypair = getGateSigningKeypair();
    const audience = config.COLLAB_SERVER_DID;
    if (keypair && audience) {
      const built = await ucans.build({
        issuer: keypair,
        audience,
        capabilities: [
          {
            with: { scheme: "collab", hierPart: docId },
            can: { namespace: "collab", segments: ["EDIT"] },
          },
        ],
        facts: [{ docId, editGrantEpoch, nullifier: shape.nullifier }],
        lifetimeInSeconds: 60 * 60 * 24 * 7, // 7 days; the editGrantEpoch re-check is the real revoke.
      });
      editUcan = ucans.encode(built);
    }
  }

  res.json({ shares, editGrantEpoch, ...(editUcan ? { editUcan } : {}) });
}

// convert:false: uniform with the other gate schemas.
export default [validate(releaseValidation, {}, { convert: false }), releaseGateShare];
