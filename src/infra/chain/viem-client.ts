import { createPublicClient, http, type PublicClient } from "viem";
import { config } from "../../config";

const CHAIN_ID_MAP = { sepolia: 11155111, gnosis: 100 } as const;

const network = config.NETWORK as keyof typeof CHAIN_ID_MAP;

/** The one chainId this gate serves; undefined for an unknown NETWORK. */
export const configuredChainId: number | undefined = CHAIN_ID_MAP[network];

let cachedPublicClient: PublicClient | undefined;

export const getPublicClient = (): PublicClient => {
  if (cachedPublicClient) return cachedPublicClient;
  if (!config.NETWORK || configuredChainId === undefined) {
    throw new Error("gate: NETWORK must be one of sepolia|gnosis");
  }
  if (!config.RPC_URL) {
    throw new Error("gate: RPC_URL is not configured");
  }
  cachedPublicClient = createPublicClient({
    transport: http(config.RPC_URL),
  });
  return cachedPublicClient;
};
