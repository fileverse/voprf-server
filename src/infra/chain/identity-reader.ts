// On-chain read of an identity module's signing DID — the anchor for verifying an
// identity UCAN (the issuer must control this DID). Read live per call, mirroring the
// portal-reader's "never cached" stance so a rotated signing key stops being trusted at once.
import { getAddress, type Hex } from "viem";
import { getPublicClient } from "./viem-client";
import { IDENTITY_MODULE_ABI } from "./identity-module-abi";

export const getIdentitySigningDid = async (
  identityContractAddress: string
): Promise<string | null> => {
  try {
    const publicClient = getPublicClient();
    const details = await publicClient.readContract({
      address: getAddress(identityContractAddress) as Hex,
      abi: IDENTITY_MODULE_ABI,
      functionName: "getIdentityModulePublicDetails",
    });
    // Tuple output: details.signingDid (index 1).
    const signingDid = (details as { signingDid?: string }).signingDid;
    return signingDid && signingDid.length > 0 ? signingDid : null;
  } catch (error) {
    console.error("gate: identity signingDid read failed:", error);
    return null;
  }
};
