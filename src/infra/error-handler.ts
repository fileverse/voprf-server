// Storage-v2-style failure expression: throwError({code,message}) at the failure
// point + one central middleware. The 500/503 bodies are static strings so no
// secret or internal error detail can transit to the client.
import { NextFunction, Request, Response } from "express";
import { BaseError } from "viem";
import { ValidationError } from "express-validation";
import { logger } from "../logger";
import { GateErrorCode } from "./gate-errors";

/** An Error carrying an HTTP status in `.code` (the throwError contract). */
interface GateError extends Error {
  code?: number;
}

// body-parser's own SyntaxError shape: never read `.body` off this, it carries
// the raw request body and must not reach a log line.
const isBodyParseError = (err: unknown): boolean =>
  err instanceof SyntaxError &&
  (err as { type?: string }).type === "entity.parse.failed" &&
  typeof (err as { status?: unknown }).status === "number";

/** Build + throw an Error whose `.code` is the HTTP status to return. */
export const throwError = ({
  code,
  message,
}: {
  code: number;
  message: string;
}): never => {
  const error = new Error(message) as GateError;
  error.code = code;
  throw error;
};

// 4-arg arity marks this as Express error middleware.
// eslint-disable-next-line no-unused-vars
export const expressErrorHandler = (
  err: GateError & { statusCode?: number },
  _req: Request,
  res: Response,
  _next: NextFunction
): void => {
  if (err instanceof ValidationError) {
    res.status(err.statusCode || 400).json({ message: err.message });
    return;
  }
  // Malformed JSON body: log only the type, never err.body (the raw request body).
  if (isBodyParseError(err)) {
    logger.warn(`gate: malformed request body (${(err as { type?: string }).type})`);
    res.status(400).json({ message: GateErrorCode.INVALID_REQUEST_BODY });
    return;
  }
  // Failed on-chain read: log the detail, surface a static retryable 503 — never
  // leak viem's internal request/url shape to the client.
  if (err instanceof BaseError) {
    logger.error("gate: viem upstream error", err);
    res.status(503).json({ message: GateErrorCode.UPSTREAM_UNAVAILABLE });
    return;
  }
  if (typeof err.code === "number") {
    res.status(err.code).json({ message: err.message });
    return;
  }
  // Unexpected: log for ops, return a static body (no err.message echo).
  logger.error("gate: unhandled error", err);
  res.status(500).json({ message: GateErrorCode.SOMETHING_WENT_WRONG });
};
