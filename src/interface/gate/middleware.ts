// Operational isolation: every /gate route 503s while Mongo is down; /voprf is unaffected.
import { NextFunction, Request, Response } from "express";
import { isMongoReady } from "../../infra/database";
import { GateErrorCode } from "../../infra/gate-errors";

export const requireGateReady = (_req: Request, res: Response, next: NextFunction): void => {
  if (!isMongoReady()) {
    res.status(503).json({ message: GateErrorCode.GATE_NOT_READY });
    return;
  }
  next();
};
