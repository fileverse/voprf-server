import { Request, Response } from "express";
import { listSession } from "../../domain/vault";
import { readVaultCookie } from "./cookie";

async function handleSession(req: Request, res: Response): Promise<void> {
  res.json(await listSession(readVaultCookie(req)));
}

export default [handleSession];
