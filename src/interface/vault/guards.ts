import { NextFunction, Request, Response } from "express";
import { GateErrorCode } from "../../infra/gate-errors";
import { throwError } from "../../infra/error-handler";
import { hasVaultStore } from "../../domain/vault/store";

// Mongo can report ready before the vault store is installed: connectGateDatastore
// only calls setVaultStore after every collection's createIndexes resolves. Without
// this guard a request landing in that window would hit getVaultStore()'s plain
// Error and surface as an unhandled 500 instead of a retryable 503.
export const requireVaultStore = (_req: Request, _res: Response, next: NextFunction): void => {
  if (!hasVaultStore()) {
    throwError({ code: 503, message: GateErrorCode.GATE_NOT_READY });
  }
  next();
};

// JSON only: a form post from a same-site page cannot reach these routes.
export const requireJson = (req: Request, res: Response, next: NextFunction): void => {
  if (req.method === "POST" && !req.is("application/json")) {
    res.status(415).json({ message: GateErrorCode.UNSUPPORTED_MEDIA_TYPE });
    return;
  }
  next();
};

export const noStore = (_req: Request, res: Response, next: NextFunction): void => {
  res.set("Cache-Control", "no-store");
  next();
};

// Carries retryAfterSeconds from the domain rate limiter into the header.
export const retryAfterHeader = (
  err: { retryAfterSeconds?: number },
  _req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (typeof err.retryAfterSeconds === "number") {
    res.set("Retry-After", String(err.retryAfterSeconds));
  }
  next(err);
};
