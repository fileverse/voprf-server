import { Request, Response } from "express";

export const VAULT_COOKIE = "fv_vault";
const MAX_AGE_MS = 400 * 24 * 60 * 60 * 1000;

export const readVaultCookie = (req: Request): string | undefined => {
  const value = (req.cookies as Record<string, unknown> | undefined)?.[VAULT_COOKIE];
  return typeof value === "string" && value.length > 0 ? value : undefined;
};

export const setVaultCookie = (res: Response, token: string): void => {
  res.cookie(VAULT_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/vault",
    maxAge: MAX_AGE_MS,
  });
};

export const clearVaultCookie = (res: Response): void => {
  res.clearCookie(VAULT_COOKIE, { httpOnly: true, secure: true, sameSite: "strict", path: "/vault" });
};
