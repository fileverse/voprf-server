// The gate's per-doc state: routing/group/bindings. All non-secret.
import { Schema, model } from "mongoose";

export interface GateAnchorRef {
  chainId: number;
  /** lowercase 0x-prefixed hex — normalized at the route boundary */
  portalAddress: string;
  fileId: number;
}

export interface GateAcceptedRoot {
  groupRef: string;
  role: "view" | "comment" | "edit";
}

export interface GateBinding {
  idHash: string;
  commitment: string;
  role: string;
}

export interface GateDocRecord {
  docId: string;
  anchorRef: GateAnchorRef;
  acceptedRoots: GateAcceptedRoot[];
  currentEpoch: number;
  /** decimal commitment strings, APPEND ORDER (clients rebuild the LeanIMT from this) */
  members: string[];
  bindings: GateBinding[];
  /** idHashes evicted by /revoke; refused at /enroll until /reinstate lifts them. */
  revokedIdHashes: string[];
  /** lowercase 0x identity-module address of the doc CREATOR, captured immutably at first
   *  register. When set, doc-scoped owner-ops additionally require a matching identity UCAN
   *  (assertDocOwnerIdentity); absent ⇒ legacy doc, collaborator-auth only. */
  ownerIdentityContract?: string;
}

const AnchorRefSchema = new Schema<GateAnchorRef>(
  {
    chainId: { type: Number, required: true },
    portalAddress: { type: String, required: true },
    fileId: { type: Number, required: true },
  },
  { _id: false }
);

const GateDocSchema = new Schema<GateDocRecord>(
  {
    docId: { type: String, required: true, unique: true },
    anchorRef: { type: AnchorRefSchema, required: true },
    acceptedRoots: [
      { groupRef: { type: String, required: true }, role: { type: String, required: true }, _id: false },
    ],
    currentEpoch: { type: Number, required: true, default: 0 },
    members: { type: [{ type: String, match: /^\d+$/ }], default: [] },
    bindings: [
      {
        idHash: { type: String, required: true },
        commitment: { type: String, required: true, match: /^\d+$/ },
        role: { type: String, required: true },
        _id: false,
      },
    ],
    revokedIdHashes: { type: [String], default: [] },
    ownerIdentityContract: { type: String, required: false },
  },
  { collection: "gate_docs", minimize: false }
);

const GateDoc = model<GateDocRecord>("GateDoc", GateDocSchema);

export default GateDoc;
