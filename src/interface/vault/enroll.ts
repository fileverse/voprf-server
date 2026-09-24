import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { enroll } from "../../domain/vault";
import { readVaultCookie, setVaultCookie } from "./cookie";

const enrollValidation = {
  body: Joi.object({ ucan: Joi.string().max(8192).required() }),
};

async function handleEnroll(req: Request, res: Response): Promise<void> {
  const { ucan } = req.body as { ucan: string };
  const result = await enroll({
    ucan,
    cookieToken: readVaultCookie(req),
    userAgent: req.get("user-agent"),
  });
  setVaultCookie(res, result.cookieToken);
  res.json({
    identityContractAddress: result.identityContractAddress,
    oprfPublicKey: result.oprfPublicKey,
    keyVersion: result.keyVersion,
  });
}

export default [validate(enrollValidation, {}, { convert: false }), handleEnroll];
