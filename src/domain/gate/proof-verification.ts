// §5.3 release checks. The encoding replica is the interop keystone: proof.message
// and proof.scope are the bigint encodings @semaphore-protocol/proof computed from
// the nonce/docId strings — the gate must reproduce them exactly, never compare raw strings.
import { verifyProof, type SemaphoreProof } from "@semaphore-protocol/proof";
import { encodeBytes32String, toBigInt as ethersToBigInt } from "ethers";
import { logger } from "../../logger";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";

export interface SemaphoreProofShape {
  merkleTreeDepth: number;
  merkleTreeRoot: string;
  nullifier: string;
  message: string;
  scope: string;
  points: string[];
}

const MIN_DEPTH = 1;
const MAX_DEPTH = 32;

// Canonical-form pinning: the gate compares message/scope/root as STRINGS against
// canonical BigInt.toString() output, so a leading-zero / 0x-hex alias would
// silently miss those comparisons. The length cap also bounds BigInt parse cost.
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_BIGINT_DECIMAL_LENGTH = 80; // BN254 field elements are ≤ 77 digits

export const isCanonicalDecimalBigInt = (value: string): boolean =>
  value.length <= MAX_BIGINT_DECIMAL_LENGTH && CANONICAL_DECIMAL.test(value);

// EXACT replica of the proof library's string→bigint wrapper (@semaphore-protocol/
// proof@4.13.1): ethers.toBigInt for decimal/0x-hex, else encodeBytes32String
// (UTF-8, ≤31 bytes). Unencodable input → 400, never a raw ethers throw.
const semaphoreBigIntEncode = (value: string): bigint => {
  try {
    return ethersToBigInt(value);
  } catch {
    try {
      return ethersToBigInt(encodeBytes32String(value));
    } catch {
      return throwError({
        code: 400,
        message: GateErrorCode.UNENCODABLE_SIGNAL,
      });
    }
  }
};

export const parseProofShape = (proof: unknown): SemaphoreProofShape => {
  if (typeof proof !== "object" || proof === null) {
    throwError({ code: 400, message: GateErrorCode.INVALID_PROOF_SHAPE });
  }
  const candidate = proof as Record<string, unknown>;
  const depth = candidate.merkleTreeDepth;
  if (typeof depth !== "number" || !Number.isInteger(depth) || depth < MIN_DEPTH || depth > MAX_DEPTH) {
    throwError({
      code: 400,
      message: GateErrorCode.INVALID_PROOF_SHAPE,
    });
  }
  for (const field of ["merkleTreeRoot", "nullifier", "message", "scope"] as const) {
    if (typeof candidate[field] !== "string") {
      throwError({ code: 400, message: GateErrorCode.INVALID_PROOF_SHAPE });
    }
    const value = candidate[field] as string;
    if (!isCanonicalDecimalBigInt(value)) {
      throwError({ code: 400, message: GateErrorCode.INVALID_PROOF_SHAPE });
    }
  }
  const points = candidate.points;
  if (
    !Array.isArray(points) ||
    points.length !== 8 ||
    points.some((p) => typeof p !== "string" || !isCanonicalDecimalBigInt(p))
  ) {
    throwError({ code: 400, message: GateErrorCode.INVALID_PROOF_SHAPE });
  }
  return candidate as unknown as SemaphoreProofShape;
};

/** Scope binds the proof to THIS doc. */
export const assertProofScope = (proof: SemaphoreProofShape, docId: string): void => {
  if (proof.scope !== semaphoreBigIntEncode(docId).toString()) {
    throwError({ code: 403, message: GateErrorCode.PROOF_SCOPE_MISMATCH });
  }
};

/** Find the live nonce whose encoding matches proof.message. */
export const matchNonceByEncodedMessage = (proofMessage: string, liveNonces: string[]): string | undefined =>
  liveNonces.find((nonce) => semaphoreBigIntEncode(nonce).toString() === proofMessage);

/** Exact CURRENT root only; stale is a self-healing retry (409), not an attack. */
export const assertCurrentRoot = (proof: SemaphoreProofShape, currentRoot: string): void => {
  if (proof.merkleTreeRoot !== currentRoot) {
    throwError({
      code: 409,
      message: GateErrorCode.STALE_GROUP_ROOT,
    });
  }
};

/**
 * Additive-implicit-group acceptance: the proof's root must be in the doc's UNION of
 * currently-accepted roots (its own implicit-group root + each attached group's root).
 * Stale (a root no longer in the set after a membership change) is a self-healing
 * retry (409), not an attack — the client refetches and rebuilds the proof.
 */
export const assertRootInSet = (proof: SemaphoreProofShape, currentRoots: string[]): void => {
  if (!currentRoots.includes(proof.merkleTreeRoot)) {
    throwError({
      code: 409,
      message: GateErrorCode.STALE_GROUP_ROOT,
    });
  }
};

/** Groth16 verify (vkeys bundled in-package; a throw → treat as invalid). */
export const assertProofValid = async (proof: SemaphoreProofShape): Promise<void> => {
  let valid = false;
  try {
    valid = await verifyProof(proof as unknown as SemaphoreProof);
  } catch (error) {
    logger.warn("gate: verifyProof threw (mapping to invalid-proof 403)", error);
    valid = false;
  }
  if (!valid) throwError({ code: 403, message: GateErrorCode.INVALID_PROOF });
};
