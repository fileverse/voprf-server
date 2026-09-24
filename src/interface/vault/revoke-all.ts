import { Request, Response } from "express";
import { validate, Joi } from "../middleware";
import { listSession, revokeAll } from "../../domain/vault";
import { clearVaultCookie, readVaultCookie, setVaultCookie } from "./cookie";
import { GateErrorCode } from "../../infra/gate-errors";

const revokeAllValidation = {
  body: Joi.object({ ucan: Joi.string().max(8192).required() }),
};

// True only for the "no live session" case listSession throws via throwError.
const isNoSessionError = (err: unknown): boolean =>
  typeof err === "object" &&
  err !== null &&
  (err as { code?: number }).code === 401 &&
  (err as { message?: string }).message === GateErrorCode.VAULT_NO_SESSION;

async function handleRevokeAll(req: Request, res: Response): Promise<void> {
  const cookieToken = readVaultCookie(req);
  const { ucan } = req.body as { ucan: string };
  const { sessionsAffected } = await revokeAll({ cookieToken, ucan });
  // The caller's session survives if it still holds other identities.
  try {
    await listSession(cookieToken);
    if (cookieToken) setVaultCookie(res, cookieToken);
  } catch (err) {
    if (!isNoSessionError(err)) throw err;
    clearVaultCookie(res);
  }
  res.json({ sessionsAffected });
}

export default [validate(revokeAllValidation, {}, { convert: false }), handleRevokeAll];
