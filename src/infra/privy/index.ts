// Privy identity-token verification via @privy-io/node. client.users().get() verifies the
// token (against the app's JWKS) and parses it into a typed User; we read the attested
// identifiers (email + wallet/smart-wallet addresses) off linked_accounts.
import { PrivyClient, type User } from "@privy-io/node";
import { importSPKI, jwtVerify } from "jose";
import { config } from "../../config";
import { throwError } from "../error-handler";
import { GateErrorCode } from "../gate-errors";

let cachedClient: PrivyClient | undefined;

// ---- DEV/HARNESS ONLY offline verification (mirrors GATE_DEV_OWNER_DID_OVERRIDE) ----
// When PRIVY_VERIFICATION_KEY is set, identity tokens are verified LOCALLY against that
// SPKI public key (the interop harness mints self-signed ES256 tokens — it cannot reach
// Privy's online JWKS). Two-layer production safety, exactly like the owner override:
// runtime-gated OFF in production (usesOfflinePrivy() requires NODE_ENV !== "production"),
// AND boot-refused if the key is nevertheless set in production (infra/gate-keys
// loadGateKeys throws). The `linked_accounts` claim is the SAME JSON-string-of-array
// shape the harness emits; the extraction loop below matches the online path so BIND
// checks stay faithful.
const usesOfflinePrivy = (): boolean =>
  !!config.PRIVY_VERIFICATION_KEY && config.NODE_ENV !== "production";

const verifyIdentityTokenOffline = async (idToken: string): Promise<string[]> => {
  let payload: Record<string, unknown>;
  try {
    const key = await importSPKI(config.PRIVY_VERIFICATION_KEY as string, "ES256");
    ({ payload } = await jwtVerify(idToken, key, { issuer: "privy.io", audience: config.PRIVY_APP_ID }));
  } catch {
    return throwError({ code: 401, message: GateErrorCode.INVALID_PRIVY_TOKEN });
  }

  let linkedAccounts: unknown;
  try {
    linkedAccounts = JSON.parse(String(payload.linked_accounts ?? "[]"));
  } catch {
    return throwError({ code: 401, message: GateErrorCode.INVALID_PRIVY_TOKEN });
  }
  if (!Array.isArray(linkedAccounts)) return [];

  const identifiers: string[] = [];
  for (const account of linkedAccounts as Record<string, unknown>[]) {
    if ("address" in account && account.address) identifiers.push(String(account.address));
    else if ("email" in account && account.email) identifiers.push(String(account.email));
  }
  return identifiers;
};

const privyClient = (): PrivyClient => {
  if (cachedClient) return cachedClient;
  if (!config.PRIVY_APP_ID) throw new Error("gate: PRIVY_APP_ID is not configured");
  if (!config.PRIVY_APP_SECRET) {
    throw new Error("gate: PRIVY_APP_SECRET is not configured");
  }
  cachedClient = new PrivyClient({
    appId: config.PRIVY_APP_ID,
    appSecret: config.PRIVY_APP_SECRET,
  });
  return cachedClient;
};

/**
 * Verify the identity token and return the attested identifiers (email + wallet/smart-wallet
 * addresses + oauth emails). Missing env → Error (500); a token Privy rejects → 401; none
 * found → [] (caller maps to 403).
 */
export const verifyIdentityToken = async (idToken: string): Promise<string[]> => {
  // DEV/HARNESS: verify locally against PRIVY_VERIFICATION_KEY before touching the
  // online client (which the harness's self-signed token can never satisfy).
  if (usesOfflinePrivy()) return verifyIdentityTokenOffline(idToken);

  // Resolve the client OUTSIDE the try so missing config stays a 500, not a 401.
  const client = privyClient();

  let user: User;
  try {
    user = await client.users().get({ id_token: idToken });
  } catch {
    return throwError({ code: 401, message: GateErrorCode.INVALID_PRIVY_TOKEN });
  }

  const identifiers: string[] = [];
  for (const account of user.linked_accounts) {
    if ("address" in account && account.address) identifiers.push(account.address);
    else if ("email" in account && account.email) identifiers.push(account.email);
  }
  return identifiers;
};
