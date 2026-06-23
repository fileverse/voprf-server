// Privy identity-token verification via @privy-io/node. client.users().get() verifies the
// token (against the app's JWKS) and parses it into a typed User; we read the attested
// identifiers (email + wallet/smart-wallet addresses) off linked_accounts.
import { PrivyClient, type User } from "@privy-io/node";
import { config } from "../../config";
import { throwError } from "../error-handler";
import { GateErrorCode } from "../gate-errors";

let cachedClient: PrivyClient | undefined;

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
