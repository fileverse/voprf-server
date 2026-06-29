import { NextFunction, Request, Response } from "express";
import { collectMemoryStats } from "./memory";
import { logger } from "../logger";

export const memoryLogger = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (req.originalUrl === "/internal/memory") {
    return next();
  }

  const before = collectMemoryStats();
  const start = Date.now();

  res.on("finish", () => {
    const after = collectMemoryStats();

    logger.info({
      method: req.method,
      path: req.originalUrl,
      statusCode: res.statusCode,
      durationMs: Date.now() - start,

      mem_before_rssMb: before.rssMb,
      mem_before_heapUsedMb: before.heapUsedMb,
      mem_before_externalMb: before.externalMb,
      
      mem_after_rssMb: after.rssMb,
      mem_after_heapUsedMb: after.heapUsedMb,
      mem_after_externalMb: after.externalMb,
      
      bn128Cached: after.bn128EngineCached
    });
  });

  next();
};