// The edit-admission signature keystone. MUST byte-match ddocs.new/…/edit-signature.ts.
// enc() reuses the proof-encoding replica; the challenge is Poseidon over (docId, nonce, "edit").
import { poseidon2, poseidon3 } from "poseidon-lite";
import { Identity } from "@semaphore-protocol/identity";
import { semaphoreBigIntEncode, isCanonicalDecimalBigInt } from "./proof-verification"; // canonical gate string→field encoding

export const editChallengeMessage = (docId: string, nonce: string): bigint =>
  poseidon3([
    semaphoreBigIntEncode(docId),
    semaphoreBigIntEncode(nonce),
    semaphoreBigIntEncode("edit"),
  ]);

export interface EddsaSignature {
  R8: [string, string];
  S: string;
}

// Every bigint-bound field must pass this before BigInt(...) — malformed input
// (wrong type, non-canonical string) must fail closed to null, never throw.
const fieldsAreCanonical = (publicKey: [string, string], signature: EddsaSignature): boolean =>
  [publicKey?.[0], publicKey?.[1], signature?.R8?.[0], signature?.R8?.[1], signature?.S].every(
    (v) => typeof v === "string" && isCanonicalDecimalBigInt(v)
  );

/** Verify the editor's signature and derive their commitment (decimal string). */
export const verifyEditSignatureAndDeriveCommitment = (
  docId: string,
  nonce: string,
  publicKey: [string, string],
  signature: EddsaSignature
): string | null => {
  try {
    if (!fieldsAreCanonical(publicKey, signature)) return null;
    const msg = editChallengeMessage(docId, nonce);
    const pk: [bigint, bigint] = [BigInt(publicKey[0]), BigInt(publicKey[1])];
    const sig = { R8: [BigInt(signature.R8[0]), BigInt(signature.R8[1])] as [bigint, bigint], S: BigInt(signature.S) };
    if (!Identity.verifySignature(msg, sig, pk)) return null;
    return Identity.generateCommitment(pk).toString();
  } catch {
    return null;
  }
};

// Per-doc actor handle, embedded in the editUcan and returned to the editor in the
// /release response. The gate always re-derives it server-side (verifyEditUcan)
// rather than trusting any client-sent value.
export const deriveEditHandle = (commitment: string, docId: string): string =>
  poseidon2([BigInt(commitment), semaphoreBigIntEncode(docId)]).toString();
