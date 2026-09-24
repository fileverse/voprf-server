import { Router } from "express";
import cookieParser from "cookie-parser";
import { asyncHandlerArray } from "../../infra/async-handler";
import { requireGateReady } from "../gate/middleware";
import { GateErrorCode } from "../../infra/gate-errors";
import { vaultCors } from "./cors";
import { noStore, requireJson, requireVaultStore, retryAfterHeader } from "./guards";
import enroll from "./enroll";
import evaluate from "./evaluate";
import leave from "./leave";
import revokeAll from "./revoke-all";
import session from "./session";

const vaultRouter = Router();

vaultRouter.use(vaultCors);
vaultRouter.use(noStore);
vaultRouter.use(cookieParser());
vaultRouter.use(requireJson);
vaultRouter.use(requireGateReady);
vaultRouter.use(requireVaultStore);
vaultRouter.post("/enroll", asyncHandlerArray(enroll));
vaultRouter.post("/evaluate", asyncHandlerArray(evaluate));
vaultRouter.post("/leave", asyncHandlerArray(leave));
vaultRouter.post("/revoke-all", asyncHandlerArray(revokeAll));
vaultRouter.get("/session", asyncHandlerArray(session));
// Keeps an unmatched /vault/* path inside this router instead of falling through
// to the app's global middleware (and its wildcard CORS) below the mount point.
vaultRouter.use((_req, res) => {
  res.status(404).json({ message: GateErrorCode.NOT_FOUND });
});
vaultRouter.use(retryAfterHeader);

export { vaultRouter };
