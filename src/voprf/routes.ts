import { Request, Response } from "express";
import { fromUint8Array, toUint8Array } from "js-base64";
import { Oprf, VOPRFServer, EvaluationRequest } from "@cloudflare/voprf-ts";
import { config } from "../config";

const suite = Oprf.Suite.P256_SHA256;

// Get public key endpoint
export function getPublicKey(req: Request, res: Response): void {
  try {
    res.json({
      publicKey: config.PUBLIC_KEY,
      suite,
    });
  } catch (error) {
    console.error("Error getting public key:", error);
    res.status(500).json({
      error: "Failed to get public key",
      message: error instanceof Error ? error.message : "Unknown error",
    });
  }
}

// Blind evaluation endpoint
export async function blindEvaluate(
  req: Request,
  res: Response
): Promise<void> {
  try {
    console.log(req.body);
    const { evaluationRequest } = req.body;
    console.log("evaluationRequest", evaluationRequest);

    if (!evaluationRequest || typeof evaluationRequest !== "string") {
      res.status(400).json({
        error: "Invalid request",
        message: "evaluationRequest must be a base64 string",
      });
      return;
    }

    const privateKey = toUint8Array(config.PRIVATE_KEY as string);
    const voprfServer = new VOPRFServer(suite, privateKey);

    const evaluationRequestBytes = toUint8Array(evaluationRequest);
    const evalReq = EvaluationRequest.deserialize(
      suite,
      evaluationRequestBytes
    );

    const evaluation = await voprfServer.blindEvaluate(evalReq);

    const evaluationData = evaluation.serialize();

    res.json({
      evaluation: fromUint8Array(evaluationData),
    });
  } catch (error) {
    console.error("Error during blind evaluation:", error);
    res.status(500).json({
      error: "Blind evaluation failed",
      message: error instanceof Error ? error.message : "Unknown error",
    });
  }
}
