// §5.2 enroll domain pieces: voucher claims validation (b) and the idHash BIND (c).
// Privy verification (a) and the owner cross-check happen in the enroll controller.
import { keccak256, toHex } from "viem";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { validateGateUcan } from "./owner-auth";

/** Byte-for-byte mirror of ddocs.new …/semaphore/normalize.ts. */
const normalizeIdentifier = (identifier: string): string => identifier.trim().toLowerCase();

const hashIdHash = (salt: string, normalizedIdentifier: string): string =>
  keccak256(toHex(`${salt}|${normalizedIdentifier}`));

export interface VoucherClaims {
  docId: string;
  groupRef: string;
  salt: string;
  idHash: string;
  role: "view" | "comment";
}

/** Validate the voucher UCAN (gate/INVITE) and its fct claims (client DocVoucherClaims). */
export const validateVoucherClaims = async (
  voucher: string,
  docId: string
): Promise<{ issuerDid: string; claims: VoucherClaims }> => {
  const { issuerDid, facts } = await validateGateUcan(voucher, docId, "INVITE");
  const fact = facts.find((f) => typeof f.idHash === "string");
  if (!fact) return throwError({ code: 403, message: GateErrorCode.INVALID_VOUCHER });

  if (fact.v !== 1) return throwError({ code: 403, message: GateErrorCode.INVALID_VOUCHER });
  if (fact.docId !== docId) return throwError({ code: 403, message: GateErrorCode.VOUCHER_DOC_MISMATCH });
  if (fact.groupRef !== docId) {
    return throwError({ code: 403, message: GateErrorCode.VOUCHER_DOC_MISMATCH });
  }
  const salt = fact.salt;
  const idHash = fact.idHash;
  const role = fact.role;
  if (typeof salt !== "string" || typeof idHash !== "string") {
    return throwError({ code: 403, message: GateErrorCode.INVALID_VOUCHER });
  }
  if (role !== "view" && role !== "comment") {
    return throwError({ code: 403, message: GateErrorCode.INVALID_VOUCHER_ROLE });
  }
  return { issuerDid, claims: { docId, groupRef: docId, salt, idHash, role } };
};

/**
 * BIND: does any Privy-attested identifier hash (with the owner-signed salt) to the
 * voucher's idHash? salt is the literal base64 string, never decoded bytes.
 */
export const bindsToAttestedIdentifier = (identifiers: string[], salt: string, idHash: string): boolean =>
  identifiers.some((identifier) => hashIdHash(salt, normalizeIdentifier(identifier)) === idHash);
