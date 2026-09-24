// On-chain read of an identity module's signing DID — the anchor for verifying an
// identity UCAN (the issuer must control this DID). Read live per call, mirroring the
// portal-reader's "never cached" stance so a rotated signing key stops being trusted at once.
import {
  BaseError,
  ContractFunctionRevertedError,
  ContractFunctionZeroDataError,
  InternalRpcError,
  getAddress,
  type Hex,
} from "viem";
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

// Vault enrollment must not read an RPC outage as "not your identity": only a
// contract-level answer maps to null, transport errors propagate as 503.
export const getIdentitySigningDidStrict = async (
  identityContractAddress: string
): Promise<string | null> => {
  try {
    const publicClient = getPublicClient();
    const details = await publicClient.readContract({
      address: getAddress(identityContractAddress) as Hex,
      abi: IDENTITY_MODULE_ABI,
      functionName: "getIdentityModulePublicDetails",
    });
    const signingDid = (details as { signingDid?: string }).signingDid;
    return signingDid && signingDid.length > 0 ? signingDid : null;
  } catch (error) {
    // viem wraps every readContract failure in ContractFunctionExecutionError, so a
    // transport error and a real "no module here" both arrive as that same outer type.
    // Walk to the actual cause: empty return data always means no module. A revert
    // also means no module, EXCEPT viem's own getContractError additionally folds a
    // bare -32603 "internal error" RPC response into ContractFunctionRevertedError
    // whenever it carries any message text, which a struggling provider does too, so
    // that path is excluded rather than trusted as a real on-chain revert.
    if (error instanceof BaseError) {
      if (error.walk((e) => e instanceof ContractFunctionZeroDataError)) return null;
      const reverted = error.walk((e) => e instanceof ContractFunctionRevertedError);
      const internalRpc = error.walk((e) => e instanceof InternalRpcError);
      if (reverted && !internalRpc) return null;
    }
    throw error;
  }
};
