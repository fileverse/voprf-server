import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { evaluate } from "../../domain/vault";
import { readVaultCookie, setVaultCookie } from "./cookie";

const evaluateValidation = {
  body: Joi.object({
    identityContractAddress: Joi.string().pattern(/^0x[0-9a-fA-F]{40}$/).required(),
    evaluationRequest: Joi.string().max(4096).required(),
    keyVersion: Joi.number().integer().min(1).required(),
  }),
};

async function handleEvaluate(req: Request, res: Response): Promise<void> {
  const cookieToken = readVaultCookie(req);
  const body = req.body as {
    identityContractAddress: string;
    evaluationRequest: string;
    keyVersion: number;
  };
  const result = await evaluate({ cookieToken, ...body });
  if (cookieToken) setVaultCookie(res, cookieToken);
  res.json(result);
}

export default [validate(evaluateValidation, {}, { convert: false }), handleEvaluate];
