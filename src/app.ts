import express, { Request, Response } from "express";

import cors from "cors";
import helmet from "helmet";
import { getPublicKey, blindEvaluate } from "./voprf/routes";

// Express App
const app = express();

// parse application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: false }));

// parse application/json
app.use(express.json());

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

// VOPRF endpoints
app.get("/voprf/public-key", getPublicKey);
app.post("/voprf/evaluate", blindEvaluate);

// Export the express app instance
export default app;
