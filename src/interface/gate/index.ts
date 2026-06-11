// /gate router. One controller per endpoint ([validate, handler]) wrapped with
// asyncHandlerArray so rejections reach the central expressErrorHandler; the
// readiness gate (503 while Mongo is down) is mounted first.
import { Router } from "express";
import { asyncHandlerArray } from "../../infra/async-handler";
import { requireGateReady } from "./middleware";
import register from "./register";
import share from "./share";
import enroll from "./enroll";
import group from "./group";
import challenge from "./challenge";
import release from "./release";
import revoke from "./revoke";

const gateRouter = Router();

gateRouter.use(requireGateReady);
gateRouter.post("/register", asyncHandlerArray(register));
gateRouter.post("/share", asyncHandlerArray(share));
gateRouter.post("/enroll", asyncHandlerArray(enroll));
gateRouter.get("/doc/:docId/group", asyncHandlerArray(group));
gateRouter.post("/challenge", asyncHandlerArray(challenge));
gateRouter.post("/release", asyncHandlerArray(release));
gateRouter.post("/revoke", asyncHandlerArray(revoke));

export { gateRouter };
