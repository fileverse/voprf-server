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
import reinstate from "./reinstate";
import relabel from "./relabel";
import groupRegister from "./group-register";
import groupGet from "./group-get";
import groupEnroll from "./group-enroll";
import groupRevoke from "./group-revoke";
import groupReinstate from "./group-reinstate";
import groupDelete from "./group-delete";
import { attach, detach } from "./attach";

const gateRouter = Router();

gateRouter.use(requireGateReady);
gateRouter.post("/register", asyncHandlerArray(register));
gateRouter.post("/share", asyncHandlerArray(share));
gateRouter.post("/enroll", asyncHandlerArray(enroll));
gateRouter.get("/doc/:docId/group", asyncHandlerArray(group));
gateRouter.post("/challenge", asyncHandlerArray(challenge));
gateRouter.post("/release", asyncHandlerArray(release));
gateRouter.post("/revoke", asyncHandlerArray(revoke));
gateRouter.post("/reinstate", asyncHandlerArray(reinstate));
gateRouter.post("/relabel", asyncHandlerArray(relabel));

// Standalone reusable groups (groups-semaphore Phase 1).
gateRouter.post("/group/register", asyncHandlerArray(groupRegister));
gateRouter.get("/group/:groupRef", asyncHandlerArray(groupGet));
gateRouter.post("/group/:groupRef/enroll", asyncHandlerArray(groupEnroll));
gateRouter.post("/group/:groupRef/revoke", asyncHandlerArray(groupRevoke));
gateRouter.post("/group/:groupRef/reinstate", asyncHandlerArray(groupReinstate));
gateRouter.post("/group/:groupRef/delete", asyncHandlerArray(groupDelete));
gateRouter.post("/doc/:docId/attach", asyncHandlerArray(attach));
gateRouter.post("/doc/:docId/detach", asyncHandlerArray(detach));

export { gateRouter };
