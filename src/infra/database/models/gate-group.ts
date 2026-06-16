// The gate's per-group state: a standalone, reusable membership set. All non-secret.
// A group has NO acceptedRoots and NO epoch (groups-semaphore §3 decision #3): group
// revoke = pull the member's commitment + binding, the computed root changes, stale
// proofs 409. It carries its own anchorRef = the host portal (chainId + portalAddress;
// fileId is unused/0 — owner-auth reads the PORTAL owner, not a file owner).
import { Schema, model } from "mongoose";
import type { GateAnchorRef, GateBinding } from "./gate-doc";

export interface GateGroupRecord {
  groupRef: string; // stable group id (shortUUID); docs reference this in acceptedRoots
  anchorRef: GateAnchorRef; // host portal (chainId, portalAddress, fileId=0) — owner-auth basis
  members: string[]; // decimal commitments, APPEND ORDER (clients rebuild the LeanIMT)
  bindings: GateBinding[]; // idHash → commitment pins (revoke-by-identifier)
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
  },
  { collection: "gate_groups", minimize: false }
);

const GateGroup = model<GateGroupRecord>("GateGroup", GateGroupSchema);

export default GateGroup;
