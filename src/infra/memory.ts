import { Request, Response } from "express";

export interface MemorySnapshot {
  bn128EngineCached: boolean;

  rssMb: number;
  heapUsedMb: number;
  heapTotalMb: number;
  externalMb: number;
  arrayBuffersMb: number;
}

const bytesToMb = (bytes: number): number =>
  Number((bytes / 1024 / 1024).toFixed(2));

export const collectMemoryStats = (): MemorySnapshot => {
  const memory = process.memoryUsage();
  const bn128Engine = (globalThis as any).curve_bn128;
  return {

    bn128EngineCached: !!bn128Engine,

    rssMb: bytesToMb(memory.rss),
    heapUsedMb: bytesToMb(memory.heapUsed),
    heapTotalMb: bytesToMb(memory.heapTotal),
    externalMb: bytesToMb(memory.external),
    arrayBuffersMb: bytesToMb(memory.arrayBuffers),
  };
};

export const getMemoryStats = (_req: Request, res: Response): void => {
  res.json(collectMemoryStats());
};