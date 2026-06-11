// POST /gate/challenge — issue a single-use nonce for a registered doc. No owner
// UCAN: anyone may request a challenge; only a valid proof (release) spends it.
import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { createGateNonce, getGateDoc } from "../../domain/gate";
import { docIdField } from "./validation";

const challengeValidation = {
  body: Joi.object({
    docId: docIdField(),
  }),
};

async function issueChallenge(req: Request, res: Response): Promise<void> {
  const { docId } = req.body as { docId: string };
  const doc = await getGateDoc(docId);
  if (!doc) return throwError({ code: 404, message: GateErrorCode.DOC_NOT_REGISTERED });
  res.json({ nonce: await createGateNonce(docId) });
}

// convert:false: uniform with the other gate schemas.
export default [validate(challengeValidation, {}, { convert: false }), issueChallenge];
