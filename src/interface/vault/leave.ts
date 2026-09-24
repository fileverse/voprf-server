import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { leave } from "../../domain/vault";
import { clearVaultCookie, readVaultCookie, setVaultCookie } from "./cookie";

const leaveValidation = {
  body: Joi.object({
    identityContractAddress: Joi.string().pattern(/^0x[0-9a-fA-F]{40}$/).required(),
  }),
};

async function handleLeave(req: Request, res: Response): Promise<void> {
  const cookieToken = readVaultCookie(req);
  const { identityContractAddress } = req.body as { identityContractAddress: string };
  const { sessionDeleted } = await leave({ cookieToken, identityContractAddress });
  if (sessionDeleted) clearVaultCookie(res);
  else if (cookieToken) setVaultCookie(res, cookieToken);
  res.status(204).end();
}

export default [validate(leaveValidation, {}, { convert: false }), handleLeave];
