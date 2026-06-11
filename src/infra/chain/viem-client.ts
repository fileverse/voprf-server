// Single-network public client: NETWORK picks the chain, RPC_URL is its endpoint.
// Created lazily (never at import) so a missing/bad NETWORK|RPC_URL surfaces as a
// gate-path error rather than crashing the process and taking the VOPRF routes
// down with it. Chainless on purpose: importing `viem/chains` drags in ox@0.14.29's
// .ts source, which fails tsc under this repo's lib:ES2020 — and read-only calls
// need no Chain object anyway.
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
