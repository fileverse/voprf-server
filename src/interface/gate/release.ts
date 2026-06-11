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
  assertCurrentRoot,
  assertProofScope,
  assertProofValid,
  computeGroupRoot,
  consumeGateNonce,
  deriveGateShare,
  getGateDoc,
  listLiveNonces,
  matchNonceByEncodedMessage,
  parseProofShape,
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

  assertCurrentRoot(shape, computeGroupRoot(doc.members));
  await assertProofValid(shape);

  // The gate's OWN currentEpoch — the client never supplies one (anti-pre-fetch).
  res.json({ gateShare: deriveGateShare(masterKey, doc.anchorRef, doc.currentEpoch) });
}

// convert:false: uniform with the other gate schemas.
export default [validate(releaseValidation, {}, { convert: false }), releaseGateShare];
