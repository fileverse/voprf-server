// getIdentityModulePublicDetails — the identity module's public struct
// { salt, signingDid, accountPublicKey, agentAddress }; the gate reads signingDid to
// root an identity UCAN. Mirrors the collaboration-server C1 verifier's fragment.
export const IDENTITY_MODULE_ABI = [
  {
    inputs: [],
    name: "getIdentityModulePublicDetails",
    outputs: [
      {
        components: [
          { internalType: "uint256", name: "salt", type: "uint256" },
          { internalType: "string", name: "signingDid", type: "string" },
          { internalType: "bytes", name: "accountPublicKey", type: "bytes" },
          { internalType: "address", name: "agentAddress", type: "address" },
        ],
        internalType: "struct IIdentityModule.IdentityPublicDetails",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;
