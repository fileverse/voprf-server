// On-chain owner-DID read: FileverseApp.files(fileId).owner → collaboratorKeys(owner).
// Read on every admin call (never cached) so ownership transfers are followed.
import { getAddress } from "viem";
import { configuredChainId, getPublicClient } from "./viem-client";
import { throwError } from "../error-handler";
import { GateErrorCode } from "../gate-errors";
import type { GateAnchorRef } from "../database/models";

// Minimal FileverseApp ABI fragments (full: ddocs.new/data/portal-contract-abi.ts).
// files() owner is output index 6.
const FILES_ABI = [
  {
    inputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    name: "files",
    outputs: [
      { internalType: "string", name: "appFileId", type: "string" },
      { internalType: "uint8", name: "fileType", type: "uint8" },
      { internalType: "string", name: "metadataIPFSHash", type: "string" },
      { internalType: "string", name: "contentIPFSHash", type: "string" },
      { internalType: "string", name: "gateIPFSHash", type: "string" },
      { internalType: "uint256", name: "version", type: "uint256" },
      { internalType: "address", name: "owner", type: "address" },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

const COLLABORATOR_KEYS_ABI = [
  {
    inputs: [{ internalType: "address", name: "", type: "address" }],
    name: "collaboratorKeys",
    outputs: [{ internalType: "string", name: "", type: "string" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

// The portal contract (FileverseApp) is OpenZeppelin-Ownable: owner() → address.
// Personal portal owner = the user; team portal owner = the workspace ASA — the same
// read covers both (groups-semaphore §11).
const OWNER_ABI = [
  {
    inputs: [],
    name: "owner",
    outputs: [{ internalType: "address", name: "", type: "address" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

export const readOnChainOwnerDid = async (anchorRef: GateAnchorRef): Promise<string> => {
  // A sepolia anchor must never be read against the gnosis gate, or vice-versa.
  if (anchorRef.chainId !== configuredChainId) {
    throwError({
      code: 400,
      message: GateErrorCode.CHAIN_ID_MISMATCH,
    });
  }

  const publicClient = getPublicClient();
  const portal = getAddress(anchorRef.portalAddress);
  const file = await publicClient.readContract({
    address: portal,
    abi: FILES_ABI,
    functionName: "files",
    args: [BigInt(anchorRef.fileId)],
  });
  const owner = file[6];
  const ownerDid = await publicClient.readContract({
    address: portal,
    abi: COLLABORATOR_KEYS_ABI,
    functionName: "collaboratorKeys",
    args: [owner],
  });
  return ownerDid;
};

// Group owner-auth basis: the on-chain PORTAL owner's DID (not a per-file owner).
// Read on every group admin call (never cached) so portal ownership transfers are
// followed.
export const readOnChainPortalOwnerDid = async (anchorRef: GateAnchorRef): Promise<string> => {
  // A sepolia anchor must never be read against the gnosis gate, or vice-versa.
  if (anchorRef.chainId !== configuredChainId) {
    throwError({
      code: 400,
      message: GateErrorCode.CHAIN_ID_MISMATCH,
    });
  }

  const publicClient = getPublicClient();
  const portal = getAddress(anchorRef.portalAddress);
  const owner = await publicClient.readContract({
    address: portal,
    abi: OWNER_ABI,
    functionName: "owner",
  });
  const ownerDid = await publicClient.readContract({
    address: portal,
    abi: COLLABORATOR_KEYS_ABI,
    functionName: "collaboratorKeys",
    args: [owner],
  });
  return ownerDid;
};

// Per-address collaborator DID. Non-empty ONLY for a CURRENT collaborator:
// registerCollaboratorKeys is onlyCollaborator and removeCollaborator clears the
// key (App.sol:529-531), so a removed collaborator returns "". Read live every
// call (never cached) so add/remove is followed immediately.
export const readCollaboratorKeyForAddress = async (
  anchorRef: GateAnchorRef,
  address: string
): Promise<string> => {
  if (anchorRef.chainId !== configuredChainId) {
    throwError({ code: 400, message: GateErrorCode.CHAIN_ID_MISMATCH });
  }
  const publicClient = getPublicClient();
  const portal = getAddress(anchorRef.portalAddress);
  const did = await publicClient.readContract({
    address: portal,
    abi: COLLABORATOR_KEYS_ABI,
    functionName: "collaboratorKeys",
    args: [getAddress(address)],
  });
  return did;
};
