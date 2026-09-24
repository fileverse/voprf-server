import * as ucans from "@ucans/ucans";
import { getIdentitySigningDidStrict } from "../../infra/chain/identity-reader";
import { getGateSigningDid } from "../../infra/gate-keys";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";
import { getVaultStore } from "./store";

export const VAULT_UCAN_MAX_LIFETIME_SECONDS = 600;
// Absolute time is checked against a wide window because a large share of
// clients run skewed clocks; single-use nonces carry replay protection instead.
export const VAULT_UCAN_SKEW_SECONDS = 86_400;

const ADDRESS_RE = /^0x[0-9a-f]{40}$/;
const JTI_RE = /^[A-Za-z0-9_-]{22,128}$/;

const invalid = (): never => throwError({ code: 401, message: GateErrorCode.INVALID_UCAN });

export const verifyVaultUcan = async (
  token: string,
  now: Date = new Date()
): Promise<{ identityContractAddress: string }> => {
  const gateDid = getGateSigningDid();
  if (!gateDid) {
    return throwError({ code: 503, message: GateErrorCode.VAULT_SIGNING_KEY_NOT_CONFIGURED });
  }

  let parsed: ucans.Ucan;
  try {
    // Signature and issuer are checked here; time bounds are checked below.
    parsed = await ucans.validate(token, { checkIsExpired: false, checkIsTooEarly: false });
  } catch {
    return invalid();
  }
  const p = parsed.payload;

  if (p.aud !== gateDid) return invalid();
  if ((p.prf ?? []).length > 0) return invalid();

  const fact = ((p.fct ?? [])[0] ?? {}) as { identityContractAddress?: unknown; jti?: unknown };
  const addr =
    typeof fact.identityContractAddress === "string"
      ? fact.identityContractAddress.toLowerCase()
      : "";
  if (!ADDRESS_RE.test(addr)) return invalid();

  const hasVaultCap = p.att.some(
    (c) =>
      c.with.scheme === "identity" &&
      c.with.hierPart.toLowerCase() === addr &&
      c.can !== "*" &&
      typeof c.can === "object" &&
      c.can.namespace === "identity" &&
      c.can.segments.length === 1 &&
      c.can.segments[0] === "VAULT"
  );
  if (!hasVaultCap) return invalid();

  const nbf = p.nbf;
  if (typeof nbf !== "number" || typeof p.exp !== "number") return invalid();
  if (p.exp - nbf <= 0 || p.exp - nbf > VAULT_UCAN_MAX_LIFETIME_SECONDS) return invalid();
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (Math.abs(nowSeconds - nbf) > VAULT_UCAN_SKEW_SECONDS) return invalid();

  // Client-generated 32-byte id; the library's own nnc is too short to rely on.
  const jti = typeof fact.jti === "string" ? fact.jti : "";
  if (!JTI_RE.test(jti)) return invalid();

  const signingDid = await getIdentitySigningDidStrict(addr);
  if (!signingDid || signingDid !== p.iss) return invalid();

  // Consumed only after every check passes so a malformed token cannot burn a nonce.
  const nonceExpiry = new Date(
    now.getTime() + (2 * VAULT_UCAN_SKEW_SECONDS + VAULT_UCAN_MAX_LIFETIME_SECONDS) * 1000
  );
  const fresh = await getVaultStore().consumeNonce(`${addr}:${jti}`, addr, nonceExpiry);
  if (!fresh) return throwError({ code: 401, message: GateErrorCode.UCAN_REPLAYED });

  return { identityContractAddress: addr };
};
