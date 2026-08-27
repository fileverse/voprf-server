import express, { Request, Response } from "express";

import cors from "cors";
import helmet from "helmet";
import { getPublicKey, blindEvaluate } from "./voprf/routes";
import { gateRouter } from "./interface/gate";
import { expressErrorHandler } from "./infra/error-handler";
import { getMemoryStats } from "./infra/memory";
import { memoryLogger } from "./infra/memoryLogger";
// Express App
const app = express();

// parse application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: false }));

// parse application/json
app.use(express.json());

app.use(memoryLogger);
// Use default logger for now

app.use(
  cors({
    origin: "*",
  })
);
app.use(
  helmet({
    contentSecurityPolicy: false,
    frameguard: false,
  })
);

// This is to check if the service is online or not
app.use("/ping", function (req: Request, res: Response) {
  res.json({ reply: "pong" });
  res.end();
});
app.get("/internal/memory", getMemoryStats);

// VOPRF endpoints
app.get("/voprf/public-key", getPublicKey);
app.post("/voprf/evaluate", blindEvaluate);

// Semaphore gate endpoints (docs/gate-server-design.md)
app.use("/gate", gateRouter);

// Central error middleware, mounted LAST — catches gate throwError + asyncHandler
// rejections. The legacy VOPRF routes handle their own errors and never reach it.
app.use(expressErrorHandler);

// Export the express app instance
export default app;
