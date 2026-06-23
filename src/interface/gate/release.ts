// POST /gate/release. LOAD-BEARING pipeline (do NOT reorder): shape → scope →
// nonce match+consume (BEFORE the verify outcome) → exact-current-root (409) →
// verifyProof (403) → derive at the gate's OWN currentEpoch.
// proof is intentionally Joi.any: parseProofShape owns ALL proof validation (incl.
// a missing/non-object proof), so its 400 messages and their position are preserved.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { getGateMasterKey } from "../../infra/gate-keys";
import {
  assertProofScope,
  assertProofValid,
  assertRootInSet,
  consumeGateNonce,
  deriveGateShare,
  getGateDoc,
  listLiveNonces,
  matchNonceByEncodedMessage,
  parseProofShape,
  resolveAcceptedRoots,
} from "../../domain/gate";
import { docIdField } from "./validation";

const releaseValidation = {
  body: Joi.object({
    docId: docIdField(),
    proof: Joi.any(),
  }),
};

async function releaseGateShare(req: Request, res: Response): Promise<void> {
  const { docId, proof } = req.body as {
    docId: string;
    proof: unknown;
  };

  const masterKey = getGateMasterKey();
  if (!masterKey) return throwError({ code: 503, message: GateErrorCode.MASTER_KEY_NOT_CONFIGURED });

  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });

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

  // Bundle by hierarchy (comment ⊇ view), derived at the gate's OWN currentEpoch.
  const shares: { view: string; comment?: string } = {
    view: deriveGateShare(masterKey, doc.anchorRef, doc.currentEpoch, "view"),
  };
  if (matchedEntry.role === "comment") {
    shares.comment = deriveGateShare(masterKey, doc.anchorRef, doc.currentEpoch, "comment");
  }
  res.json({ shares });
}

// convert:false: uniform with the other gate schemas.
export default [validate(releaseValidation, {}, { convert: false }), releaseGateShare];
