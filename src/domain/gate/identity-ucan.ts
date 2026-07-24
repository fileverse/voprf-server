// Identity-contract proof for gate owner-ops. A gate-audienced UCAN that proves the caller
// controls a specific on-chain identity module: the signed fact + capability carry the
// identityContractAddress, and the token must be rooted at that module's on-chain signingDid.
// Mirrors the collaboration-server C1 verifier (auth.ts verifyIdentityToken), audienced to the
// gate DID so a collab-audienced identity token cannot replay here. Used to bind a doc to its
// creator's identity (assertDocOwnerIdentity), distinguishing individuals behind a shared
// workspace collaborator credential. See docs/architecture/gp-semaphore.md.
import * as ucans from "@ucans/ucans";
import { getIdentitySigningDid } from "../../infra/chain/identity-reader";
import { getGateSigningDid } from "../../infra/gate-keys";

export const verifyIdentityUcan = async (
  token: string
): Promise<{ identityContractAddress: string } | null> => {
  const gateDid = getGateSigningDid();
  if (!gateDid) return null; // identity binding disabled until GATE_SIGNING_KEY is pinned

  try {
    // Peek the signed fact for the claimed identity contract (validate checks the token's own
    // signature + time + audience shape; the rootIssuer cross-check is enforced by verify below).
    const parsed = await ucans.validate(token);
    const fact = ((parsed.payload.fct ?? [])[0] ?? {}) as {
      identityContractAddress?: string;
    };
    const addr = fact.identityContractAddress?.toLowerCase();
    if (!addr || !addr.startsWith("0x")) return null; // fail closed: no signed address

    // The on-chain read is the anchor — the token must be rooted at the identity module's
    // signingDid, so a caller cannot claim an identity contract they do not control.
    const signingDid = await getIdentitySigningDid(addr);
    if (!signingDid) return null;

    const result = await ucans.verify(token, {
      audience: gateDid,
      requiredCapabilities: [
        {
          capability: {
            with: { scheme: "identity", hierPart: addr },
            can: { namespace: "identity", segments: ["PROVE"] },
          },
          rootIssuer: signingDid,
        },
      ],
    });
    return result.ok ? { identityContractAddress: addr } : null;
  } catch (error) {
    console.error("gate: identity UCAN verification failed:", error);
    return null;
  }
};
