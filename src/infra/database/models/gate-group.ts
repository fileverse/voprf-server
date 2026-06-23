
import { Schema, model } from "mongoose";
import type { GateAnchorRef, GateBinding } from "./gate-doc";

export interface GateGroupRecord {
  groupRef: string; // stable group id (shortUUID); docs reference this in acceptedRoots
  anchorRef: GateAnchorRef; // host portal (chainId, portalAddress, fileId=0) — owner-auth basis
  members: string[]; // decimal commitments, APPEND ORDER (clients rebuild the LeanIMT)
  bindings: GateBinding[]; // idHash → commitment pins (revoke-by-identifier)
  /** idHashes evicted by /group/:ref/revoke; refused at group /enroll until /reinstate. */
  revokedIdHashes: string[];
}

const AnchorRefSchema = new Schema<GateAnchorRef>(
  {
    chainId: { type: Number, required: true },
    portalAddress: { type: String, required: true },
    fileId: { type: Number, required: true },
  },
  { _id: false }
);

const GateGroupSchema = new Schema<GateGroupRecord>(
  {
    groupRef: { type: String, required: true, unique: true },
    anchorRef: { type: AnchorRefSchema, required: true },
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
  },
  { collection: "gate_groups", minimize: false }
);

const GateGroup = model<GateGroupRecord>("GateGroup", GateGroupSchema);

export default GateGroup;
