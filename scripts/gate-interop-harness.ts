// gate-interop-harness.ts — plays the ddocs.new GP client byte-for-byte against
// a locally spawned gate (docs/gate-server-design.md §11, scenarios H1–H25; H10 retired with key
// versioning). H22–H24 cover the per-role (view/comment) boundary: distinct role shares, the
// crypto boundary (view unwraps fileKey only), and the enroll role-relabel tier-switch primitive.
// H25 covers whole-group DELETE: one delete hard-revokes across every attached doc (no per-doc
// fan-out), live roots on a doc survive, and re-delete is idempotent (404).
// H26–H28 cover the per-doc/per-group revokedIdHashes denylist and reinstate:
//   H26: /revoke (with denylist) blocks re-enroll → 403 IDENTITY_REVOKED; /reinstate lifts it.
//   H27: group /revoke blocks re-enroll on the group → 403 IDENTITY_REVOKED; group /reinstate lifts it.
//   H28: /revoke with addToDenylist:false (mechanical epoch-bump) leaves the denylist untouched —
//        a currently-valid, never-denylisted member's /enroll succeeds (not 403).
// NO test framework: scenarios run sequentially, one "Hn … ok" line each; the
// first failed assertion throws with a diagnostic and the process exits 1.
//
// Client replicas in here mirror (ground truth, do not drift):
//   ddocs.new/utils/private-access-scheme/semaphore/{blob,normalize,owner-ucan,voucher,reader,gate-client}.ts
//   ddocs.new/utils/identity-utils/aes-utils.ts (AES-256-GCM, 24-byte IV prepended, base64)
//
// Prereqs: local mongod on 27017 (uses ONLY the throwaway db below — dropped at
// start and end); network on first run (Semaphore snark artifact download).
// Run: npx ts-node --transpile-only scripts/gate-interop-harness.ts
import { spawn, type ChildProcess } from "child_process";
import { once } from "events";
import { randomBytes, webcrypto } from "crypto";
import mongoose from "mongoose";
import * as ucans from "@ucans/ucans";
import { Identity } from "@semaphore-protocol/identity";
import { Group } from "@semaphore-protocol/group";
import { generateProof } from "@semaphore-protocol/proof";
import { SignJWT, exportSPKI, generateKeyPair } from "jose";
import { keccak256, toHex } from "viem";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

const GATE_PORT = 4990;
const GATE_URL = `http://127.0.0.1:${GATE_PORT}/gate`;
// Dedicated throwaway database — dropped at run start and run end. NEVER point
// this at a database name shared with anything else on the developer's mongod.
const HARNESS_DB_NAME = "fv_gate_interop_harness";
const MONGO_URI = `mongodb://localhost:27017/${HARNESS_DB_NAME}`;
const PRIVY_APP_ID = "gate-harness-app";
const HKDF_INFO = "gp-filekey-wrap-v2"; // client blob.ts spec §15.13
const GCM_IV_LENGTH = 24; // client crypto-utils NONCE_LENGTH
// Gate boot: poll /ping up to BOOT_POLL_ATTEMPTS times, BOOT_POLL_INTERVAL_MS apart.
const BOOT_POLL_ATTEMPTS = 60;
const BOOT_POLL_INTERVAL_MS = 500;

// ---------- assertions (throw on FIRST failure; never weaken, never print key material) ----------
class CheckFailure extends Error {}

const ensure = (scenario: string, label: string, ok: boolean, detail?: string): void => {
  if (!ok) {
    throw new CheckFailure(`${scenario} failed at "${label}"${detail ? `\n  ${detail}` : ""}`);
  }
};

interface GateReply {
  status: number;
  body: Record<string, unknown> | undefined;
}

/** Diagnostic-safe body: share material (now the per-role `shares` bundle) must never reach stdout. */
const redactedBody = (reply: GateReply): string =>
  JSON.stringify(
    reply.body && "shares" in reply.body ? { ...reply.body, shares: "<redacted>" } : reply.body
  );

/**
 * Assert HTTP status and (optionally) the exact `message` text. The error body
 * is now `{ message }` (storage-v2 style) — the old stable `error` CATEGORY
 * field no longer exists, so disambiguation between two failures that share a
 * status is done by pinning the exact `message` string (read verbatim from the
 * throwing code in src/domain/gate/* and src/interface/gate/*).
 */
const ensureReply = (
  scenario: string,
  label: string,
  reply: GateReply,
  wantStatus: number,
  wantMessage?: string
): void => {
  ensure(
    scenario,
    label,
    reply.status === wantStatus,
    `expected HTTP ${wantStatus}, got ${reply.status} body=${redactedBody(reply)}`
  );
  if (wantMessage !== undefined) {
    ensure(
      scenario,
      label,
      reply.body?.message === wantMessage,
      `expected message "${wantMessage}", got body=${redactedBody(reply)}`
    );
  }
};

// ---------- HTTP (mirrors the client's callGate transport, but surfaces status) ----------
const callGate = async (method: "GET" | "POST", path: string, body?: unknown): Promise<GateReply> => {
  const res = await fetch(`${GATE_URL}${path}`, {
    method,
    ...(body !== undefined && {
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? (JSON.parse(text) as Record<string, unknown>) : undefined };
};

// ---------- client replicas (must stay byte-identical to ddocs.new) ----------
/** …/semaphore/normalize.ts */
const normalizeIdentifier = (identifier: string): string => identifier.trim().toLowerCase();
const hashIdHash = (salt: string, normalized: string): string => keccak256(toHex(`${salt}|${normalized}`));

/** …/semaphore/blob.ts deriveWrapKey: HKDF-SHA256(seed‖gateShare, salt, info) → 32B AES key. */
const deriveWrapKeyBytes = (seedB64: string, gateShareB64: string, saltB64: string): Uint8Array => {
  const seed = Buffer.from(seedB64, "base64");
  const share = Buffer.from(gateShareB64, "base64");
  const ikm = Buffer.concat([seed, share]);
  return hkdf(sha256, ikm, Buffer.from(saltB64, "base64"), Buffer.from(HKDF_INFO, "utf8"), 32);
};

/** …/identity-utils/aes-utils.ts encryptAES: AES-256-GCM, 24-byte random IV prepended, base64. */
const wrapWithKey = async (plaintext: Uint8Array, keyBytes: Uint8Array): Promise<string> => {
  const key = await webcrypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(GCM_IV_LENGTH);
  const encrypted = new Uint8Array(await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  return Buffer.concat([iv, encrypted]).toString("base64");
};

const unwrapWithKey = async (wrappedB64: string, keyBytes: Uint8Array): Promise<Uint8Array | undefined> => {
  const bytes = Buffer.from(wrappedB64, "base64");
  const key = await webcrypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  try {
    return new Uint8Array(
      await webcrypto.subtle.decrypt(
        { name: "AES-GCM", iv: bytes.subarray(0, GCM_IV_LENGTH) },
        key,
        bytes.subarray(GCM_IV_LENGTH)
      )
    );
  } catch {
    return undefined;
  }
};

// ---------- throwaway-db lifecycle (touches ONLY fv_gate_interop_harness) ----------
const dropHarnessDb = async (): Promise<void> => {
  const conn = await mongoose
    .createConnection(MONGO_URI, { serverSelectionTimeoutMS: 5000 })
    .asPromise();
  await conn.dropDatabase();
  await conn.close();
};

// ---------- gate spawn / teardown ----------
let gate: ChildProcess | undefined;
// True only once the child's `exit` event has fired. NOT `.killed` — that flips
// as soon as ANY signal is sent (even one the child survived), which would turn
// the backstops below into no-ops after the first SIGTERM. `.exitCode` is no
// better: it stays null when the child dies BY a signal.
let gateExited = false;

const killGate = (): void => {
  if (gate && !gateExited) gate.kill("SIGTERM");
};
// Backstops: a thrown error path is covered by main's finally; signals + exit
// still kill the child so it can never outlive the harness.
process.on("exit", killGate);
process.on("SIGINT", () => {
  killGate();
  process.exit(130);
});
process.on("SIGTERM", () => {
  killGate();
  process.exit(143);
});

const startGate = async (env: NodeJS.ProcessEnv): Promise<ChildProcess> => {
  const child = spawn("node", ["-r", "ts-node/register/transpile-only", "src/index.ts"], {
    cwd: process.cwd(),
    env: { ...process.env, ...env },
    stdio: ["ignore", "inherit", "inherit"],
  });
  gate = child; // visible to the kill backstops even if boot times out below
  child.once("exit", () => {
    gateExited = true;
  });
  for (let attempt = 0; attempt < BOOT_POLL_ATTEMPTS; attempt += 1) {
    if (child.exitCode !== null) break; // crashed during boot — stop polling
    try {
      const res = await fetch(`http://127.0.0.1:${GATE_PORT}/ping`);
      if (res.ok) return child;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, BOOT_POLL_INTERVAL_MS));
  }
  child.kill("SIGTERM");
  throw new Error(
    `gate did not become ready within ${(BOOT_POLL_ATTEMPTS * BOOT_POLL_INTERVAL_MS) / 1000}s`
  );
};

const stopGate = async (): Promise<void> => {
  if (!gate) return;
  if (!gateExited) {
    const exited = once(gate, "exit");
    gate.kill("SIGTERM");
    await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 5000))]);
    if (!gateExited) {
      // SIGTERM ignored for 5s — escalate. SIGKILL cannot be trapped.
      gate.kill("SIGKILL");
      await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 5000))]);
    }
  }
  console.log("gate server stopped");
};

const main = async (): Promise<void> => {
  // ---- identities & trust roots (generated fresh per run; never printed) ----
  const ownerKeypair = await ucans.EdKeypair.create();
  const ownerDid = ownerKeypair.did();
  const intruderKeypair = await ucans.EdKeypair.create();

  const { publicKey: privyPublic, privateKey: privyPrivate } = await generateKeyPair("ES256");
  const privyPem = await exportSPKI(privyPublic);

  const masterKey = randomBytes(32).toString("base64");

  try {
    // Clean slate BEFORE the server connects (also proves mongod reachability).
    await dropHarnessDb();
    console.log(`throwaway db ${HARNESS_DB_NAME} dropped (pre-run)`);

    gate = await startGate({
      PORT: String(GATE_PORT),
      MONGO_URI,
      GATE_MASTER_KEY: masterKey,
      // Single-network chain config (replaces the removed multi-chain
      // GATE_CHAIN_RPC_URLS map). RPC_URL is NEVER dialed: GATE_DEV_OWNER_DID_OVERRIDE
      // short-circuits readOnChainOwnerDid before any viem client is built, so no
      // network round-trip — and the anchorRef.chainId-match check — is reached.
      NETWORK: "sepolia",
      RPC_URL: "https://rpc.sepolia.org",
      GATE_DEV_OWNER_DID_OVERRIDE: ownerDid,
      PRIVY_VERIFICATION_KEY: privyPem,
      PRIVY_APP_ID,
      NODE_ENV: "development",
    });
    console.log("gate server ready");

    // ---- per-run fixtures ----
    const runTag = randomBytes(4).toString("hex");
    const docId = `hd-${runTag}-a`; // 13 chars — comfortably under the 31-byte scope ceiling
    const docIdB = `hd-${runTag}-b`;
    const anchorRef = {
      // sepolia — matches the spawned gate's NETWORK. Not strictly load-bearing
      // here (the dev-owner override short-circuits the chainId-match check), but
      // kept realistic for parity with the manual staging run on a real chain.
      chainId: 11155111,
      portalAddress: `0x${randomBytes(20).toString("hex")}`,
      fileId: 7,
    };
    const salt = randomBytes(32).toString("base64");
    const seed = randomBytes(32).toString("base64");
    const memberOneEmail = "member-one@example.com";
    const memberTwoEmail = "Member-Two@Example.COM"; // raw mixed case — exercises BOTH sides' normalize
    const outsiderEmail = "outsider@example.com";

    const memberOne = new Identity(`harness-member-one-${runTag}`);
    const memberTwo = new Identity(`harness-member-two-${runTag}`);
    const memberOneCommitment = memberOne.commitment.toString();
    const memberTwoCommitment = memberTwo.commitment.toString();

    // Client mint replica (owner-ucan.ts mintGateOwnerUcan): SELF-audience —
    // audience is the ISSUER's own DID (the gate enforces aud === iss), 5-min life.
    const mintAdminUcan = async (forDocId: string, keypair: ucans.EdKeypair = ownerKeypair): Promise<string> =>
      ucans.encode(
        await ucans.build({
          audience: keypair.did(),
          issuer: keypair,
          lifetimeInSeconds: 300,
          capabilities: [
            { with: { scheme: "gate", hierPart: forDocId }, can: { namespace: "gate", segments: ["ADMIN"] } },
          ],
        })
      );

    // Client mint replica (voucher.ts mintVoucher → owner-ucan.ts mintDocScopedUcan).
    const mintVoucher = async (
      forDocId: string,
      identifier: string,
      role: "view" | "comment" = "view"
    ): Promise<{ token: string; idHash: string }> => {
      const idHash = hashIdHash(salt, normalizeIdentifier(identifier));
      const token = ucans.encode(
        await ucans.build({
          audience: ownerDid,
          issuer: ownerKeypair,
          lifetimeInSeconds: 30 * 86400,
          capabilities: [
            { with: { scheme: "gate", hierPart: forDocId }, can: { namespace: "gate", segments: ["INVITE"] } },
          ],
          facts: [{ v: 1, docId: forDocId, groupRef: forDocId, salt, idHash, role, iat: Date.now() }],
        })
      );
      return { token, idHash };
    };

    // ---- group-scoped client mint replicas (NEW client path: groups-semaphore) ----
    // Client mint replica (owner-ucan.ts mintGroupOwnerUcan): SELF-audience, gate/ADMIN
    // on the GROUP hierPart (groupId), 5-min life. Used for /group/register, /revoke,
    // and to authorize /doc/:docId/attach is the DOC-scoped admin UCAN (mintAdminUcan).
    const mintGroupAdminUcan = async (
      groupId: string,
      keypair: ucans.EdKeypair = ownerKeypair
    ): Promise<string> =>
      ucans.encode(
        await ucans.build({
          audience: keypair.did(),
          issuer: keypair,
          lifetimeInSeconds: 300,
          capabilities: [
            { with: { scheme: "gate", hierPart: groupId }, can: { namespace: "gate", segments: ["ADMIN"] } },
          ],
        })
      );

    // Client mint replica (group-voucher.ts mintGroupVoucher → owner-ucan.ts
    // mintGroupScopedUcan): gate/INVITE on the GROUP hierPart, fct.groupRef = groupId,
    // NO docId (a group voucher is reusable across every doc the group is attached to).
    const mintGroupVoucher = async (
      groupId: string,
      identifier: string,
      role: "view" | "comment" = "view"
    ): Promise<{ token: string; idHash: string }> => {
      const idHash = hashIdHash(salt, normalizeIdentifier(identifier));
      const token = ucans.encode(
        await ucans.build({
          audience: ownerDid,
          issuer: ownerKeypair,
          lifetimeInSeconds: 30 * 86400,
          capabilities: [
            { with: { scheme: "gate", hierPart: groupId }, can: { namespace: "gate", segments: ["INVITE"] } },
          ],
          facts: [{ v: 1, groupRef: groupId, salt, idHash, role, iat: Date.now() }],
        })
      );
      return { token, idHash };
    };

    // Privy-shaped identity token (the harness's ES256 key IS the trust root).
    const mintPrivyToken = async (emails: string[]): Promise<string> =>
      new SignJWT({
        linked_accounts: JSON.stringify(emails.map((address) => ({ type: "email", address }))),
      })
        .setProtectedHeader({ alg: "ES256" })
        .setIssuer("privy.io")
        .setAudience(PRIVY_APP_ID)
        .setSubject("did:privy:harness")
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(privyPrivate);

    type RoleGroup = { root: string; members: string[] };
    type DocGroupRoles = { view: RoleGroup; comment: RoleGroup };

    // The doc group endpoint now returns per-role lists. Existing scenarios use the VIEW
    // role (their implicit group registers as "view"), so fetchGroup defaults to that list;
    // fetchDocGroupRoles exposes both for the role-aware release path (and H23/H24).
    const fetchDocGroupRoles = async (scenario: string, forDocId: string): Promise<DocGroupRoles> => {
      const reply = await callGate("GET", `/doc/${forDocId}/group`);
      ensure(scenario, `GET /doc/${forDocId}/group`, reply.status === 200, `got ${reply.status}`);
      return reply.body as unknown as DocGroupRoles;
    };

    const fetchGroup = async (scenario: string, forDocId: string): Promise<RoleGroup> =>
      (await fetchDocGroupRoles(scenario, forDocId)).view;

    /** POST /challenge, response-checked: asserts 200 + a non-empty string nonce, returns it. */
    const mintChallenge = async (scenario: string, forDocId: string): Promise<string> => {
      const reply = await callGate("POST", "/challenge", { docId: forDocId });
      ensureReply(scenario, `POST /challenge for ${forDocId}`, reply, 200);
      const nonce = reply.body?.nonce;
      ensure(
        scenario,
        `challenge for ${forDocId} returns a non-empty string nonce`,
        typeof nonce === "string" && nonce.length > 0,
        redactedBody(reply)
      );
      return nonce as string;
    };

    /** Full member release flow (reader.ts §2–4): challenge → local LeanIMT → proof → /release.
     * Role-aware: with no override, prove the role-filtered root that CONTAINS this identity's
     * commitment (comment set if present, else view) — mirroring the real client (Task 2.3). */
    const releaseAs = async (
      scenario: string,
      identity: Identity,
      forDocId: string,
      membersOverride?: string[]
    ): Promise<GateReply> => {
      const nonce = await mintChallenge(scenario, forDocId);
      let members: string[];
      if (membersOverride) {
        members = membersOverride;
      } else {
        const roles = await fetchDocGroupRoles(scenario, forDocId);
        const me = identity.commitment.toString();
        members = roles.comment.members.includes(me) ? roles.comment.members : roles.view.members;
      }
      const group = new Group(members.map(BigInt));
      const proof = await generateProof(identity, group, nonce, forDocId); // message=nonce, scope=docId
      return callGate("POST", "/release", { docId: forDocId, proof });
    };

    /** GET /group/:groupRef → root+members (the standalone group reader). */
    const fetchGateGroup = async (
      scenario: string,
      groupRef: string
    ): Promise<{ root: string; members: string[] }> => {
      const reply = await callGate("GET", `/group/${groupRef}`);
      ensure(scenario, `GET /group/${groupRef}`, reply.status === 200, `got ${reply.status}`);
      return reply.body as unknown as { root: string; members: string[] };
    };

    // NEW client path (group-reader.ts resolveGroupAccess §2–4): the member proves the
    // GROUP's root but the proof SCOPE is the docId being opened (the doc supplies the
    // scope, the group supplies the root). membersOverride proves against a stale member
    // set (post-revoke / detach negative tests).
    const releaseViaGroup = async (
      scenario: string,
      identity: Identity,
      forDocId: string,
      groupRef: string,
      membersOverride?: string[]
    ): Promise<GateReply> => {
      const nonce = await mintChallenge(scenario, forDocId);
      const members = membersOverride ?? (await fetchGateGroup(scenario, groupRef)).members;
      const group = new Group(members.map(BigInt));
      const proof = await generateProof(identity, group, nonce, forDocId); // root=group, scope=docId
      return callGate("POST", "/release", { docId: forDocId, proof });
    };

    // ================= H1: register → share → enroll → group → release =================
    const h1 = "H1";
    const registerReply = await callGate("POST", "/register", {
      docId,
      acceptedRoots: [{ groupRef: docId, role: "view" }],
      ownerUcan: await mintAdminUcan(docId),
      anchorRef,
    });
    ensureReply(h1, "register", registerReply, 200);
    ensure(h1, "register currentEpoch 0", registerReply.body?.currentEpoch === 0, redactedBody(registerReply));

    const shareEpoch0 = await callGate("POST", "/share", {
      docId,
      epoch: 0,
      ownerUcan: await mintAdminUcan(docId),
    });
    ensureReply(h1, "share epoch 0", shareEpoch0, 200);
    const ownerShares0 = shareEpoch0.body?.shares as { view: string; comment: string };
    const ownerShare0 = ownerShares0?.view;
    ensure(h1, "share view decodes to 32 bytes", Buffer.from(ownerShare0 ?? "", "base64").length === 32);
    ensure(
      h1,
      "owner /share also returns a comment share",
      Buffer.from(ownerShares0?.comment ?? "", "base64").length === 32
    );

    const voucherOne = await mintVoucher(docId, memberOneEmail);
    const enrollOne = await callGate("POST", "/enroll", {
      docId,
      voucher: voucherOne.token,
      commitment: memberOneCommitment,
      privyIdToken: await mintPrivyToken([memberOneEmail]),
    });
    ensureReply(h1, "enroll member one", enrollOne, 204);

    const groupAfterOne = await fetchGroup(h1, docId);
    ensure(
      h1,
      "group read-after-write is exactly [memberOne]",
      groupAfterOne.members.length === 1 && groupAfterOne.members[0] === memberOneCommitment,
      `members=${JSON.stringify(groupAfterOne.members)}` // commitments are public values
    );
    ensure(
      h1,
      "group root matches local LeanIMT",
      groupAfterOne.root === new Group(groupAfterOne.members.map(BigInt)).root.toString()
    );

    const releaseOne = await releaseAs(h1, memberOne, docId);
    ensureReply(h1, "release (single-member group, depth-1 proof)", releaseOne, 200);
    const memberShares0 = releaseOne.body?.shares as { view: string; comment?: string };
    const memberShare0 = memberShares0?.view;
    ensure(h1, "CORE share(view,0) === release(view) bytes", ownerShare0 === memberShare0, "view share bytes mismatch");
    ensure(h1, "view member gets NO comment share", memberShares0?.comment === undefined);
    console.log("H1 register/share/enroll/group/release + view-share byte-equality ... ok");

    // ================= H2: end-to-end wrap/unwrap through both shares =================
    const h2 = "H2";
    // Known-answer pin: frozen from the client-verified replica (blob.ts
    // deriveWrapKey, 2026-06-10). The round-trip below wraps AND unwraps with
    // the harness's own replica, so it would pass for ANY internally-consistent
    // HKDF — this pin is what catches REPLICA drift. A deliberate client-side
    // change to the derivation must update this vector. All inputs/outputs here
    // are fixed public test vectors (NOT key material), so printing the
    // expected/actual hex on failure is safe and useful.
    const katSeed = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="; // bytes 0x00..0x1f
    const katShare = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="; // bytes 0x20..0x3f
    const katSalt = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="; // bytes 0x40..0x5f
    const katExpectedHex = "28018ff661059dbbfdc10db91f77a02d72b5fe052a87830ce80d6df3edaab470";
    const katActualHex = Buffer.from(deriveWrapKeyBytes(katSeed, katShare, katSalt)).toString("hex");
    ensure(
      h2,
      "deriveWrapKey known-answer vector (replica drift pin)",
      katActualHex === katExpectedHex,
      `expected ${katExpectedHex}\n  got      ${katActualHex}`
    );
    const fileKey = randomBytes(32);
    const wrapped = await wrapWithKey(fileKey, deriveWrapKeyBytes(seed, ownerShare0, salt));
    const unwrapped = await unwrapWithKey(wrapped, deriveWrapKeyBytes(seed, memberShare0, salt));
    ensure(
      h2,
      "CORE member-side unwrap restores the fileKey",
      !!unwrapped && Buffer.from(unwrapped).equals(fileKey),
      "wrap/unwrap round-trip failed (replica-internal asymmetry)"
    );
    console.log("H2 deriveWrapKey known-answer pin + wrapKey round-trip (/share wrap, /release unwrap) ... ok");

    // ================= H3: second member, order preserved =================
    const h3 = "H3";
    const voucherTwo = await mintVoucher(docId, memberTwoEmail);
    const enrollTwo = await callGate("POST", "/enroll", {
      docId,
      voucher: voucherTwo.token,
      commitment: memberTwoCommitment,
      privyIdToken: await mintPrivyToken([memberTwoEmail]), // raw mixed case — server must normalize
    });
    ensureReply(h3, "enroll member two", enrollTwo, 204);
    const groupAfterTwo = await fetchGroup(h3, docId);
    ensure(
      h3,
      "members in append order",
      groupAfterTwo.members[0] === memberOneCommitment && groupAfterTwo.members[1] === memberTwoCommitment,
      `members=${JSON.stringify(groupAfterTwo.members)}`
    );
    ensureReply(h3, "member one still releases", await releaseAs(h3, memberOne, docId), 200);
    ensureReply(h3, "member two releases", await releaseAs(h3, memberTwo, docId), 200);
    console.log("H3 second enroll preserves append order; both members release ... ok");

    // ================= H4: BIND failure =================
    const h4 = "H4";
    const voucherOutsider = await mintVoucher(docId, outsiderEmail);
    const bindFail = await callGate("POST", "/enroll", {
      docId,
      voucher: voucherOutsider.token,
      commitment: new Identity(`harness-outsider-${runTag}`).commitment.toString(),
      privyIdToken: await mintPrivyToken([memberOneEmail]), // attests member-one, voucher is for outsider
    });
    // Pin the exact BIND message: 403 is shared with the scope/nonce/owner checks,
    // so the message is what proves the rejection is specifically the BIND check.
    // (exact throw text of enrollMember's BIND failure — src/interface/gate/enroll.ts)
    ensureReply(h4, "BIND mismatch", bindFail, 403, "BIND_MISMATCH");
    console.log("H4 BIND mismatch (Privy attests a non-matching identifier) 403 ... ok");

    // ================= H5: pin =================
    const h5 = "H5";
    const reEnroll = await callGate("POST", "/enroll", {
      docId,
      voucher: voucherOne.token,
      commitment: memberOneCommitment,
      privyIdToken: await mintPrivyToken([memberOneEmail]),
    });
    ensureReply(h5, "same (idHash, C) re-enroll", reEnroll, 204);
    ensure(h5, "no duplicate member appended", (await fetchGroup(h5, docId)).members.length === 2);
    const pinConflict = await callGate("POST", "/enroll", {
      docId,
      voucher: voucherOne.token,
      commitment: new Identity(`harness-evil-${runTag}`).commitment.toString(),
      privyIdToken: await mintPrivyToken([memberOneEmail]),
    });
    // 409 message pinned (exact throw text — src/interface/gate/enroll.ts): the
    // enroll pin-conflict 409 is distinct from the revoke stale-epoch and register
    // anchor-conflict 409s, which carry different messages.
    ensureReply(
      h5,
      "different C for bound idHash",
      pinConflict,
      409,
      "COMMITMENT_PINNED"
    );
    console.log("H5 idempotent re-enroll 204; different-commitment pin conflict 409 ... ok");

    // ================= H6: revoke (the three-cut, gate side) =================
    const h6 = "H6";
    const preRevokeMembers = (await fetchGroup(h6, docId)).members;
    const shareEpoch1 = await callGate("POST", "/share", {
      docId,
      epoch: 1,
      ownerUcan: await mintAdminUcan(docId),
    });
    ensureReply(h6, "owner pulls epoch-1 share before the cut", shareEpoch1, 200);
    const ownerShare1 = (shareEpoch1.body?.shares as { view: string })?.view;
    // Presence first — a missing/renamed key must fail loudly, not satisfy `undefined !== x`.
    ensure(h6, "epoch-1 view share decodes to 32 bytes", Buffer.from(ownerShare1 ?? "", "base64").length === 32);
    ensure(h6, "epoch-1 share differs from epoch-0", ownerShare1 !== ownerShare0, "view share bytes identical");

    const revokeTwo = await callGate("POST", "/revoke", {
      docId,
      idHash: voucherTwo.idHash,
      ownerUcan: await mintAdminUcan(docId),
      epoch: 1,
    });
    ensureReply(h6, "revoke member two", revokeTwo, 204);
    ensure(h6, "member two evicted from group", !(await fetchGroup(h6, docId)).members.includes(memberTwoCommitment));

    const staleProofReply = await releaseAs(h6, memberTwo, docId, preRevokeMembers);
    // 409 message pinned (exact throw text of assertCurrentRoot —
    // src/domain/gate/proof-verification.ts): distinguishes this stale-ROOT 409
    // on /release from the stale-EPOCH (H8) and anchor-conflict (H11) 409s.
    ensureReply(
      h6,
      "removed member's pre-revoke-root proof",
      staleProofReply,
      409,
      "STALE_GROUP_ROOT"
    );

    const survivorRelease = await releaseAs(h6, memberOne, docId);
    ensureReply(h6, "survivor releases at epoch 1", survivorRelease, 200);
    ensure(
      h6,
      "survivor receives the epoch-1 share",
      (survivorRelease.body?.shares as { view: string })?.view === ownerShare1,
      "view share bytes mismatch vs owner's epoch-1 pull"
    );
    console.log("H6 revoke: stale-root 409 for removed member; survivor gets the epoch-1 share ... ok");

    // ================= H7: revoke replay / rollback =================
    const h7 = "H7";
    const revokeReplay = await callGate("POST", "/revoke", {
      docId,
      idHash: voucherTwo.idHash,
      ownerUcan: await mintAdminUcan(docId),
      epoch: 1,
    });
    ensureReply(h7, "same-epoch revoke replay", revokeReplay, 204);
    // Implemented routes validate epoch >= 1 up front (epoch 0 is never a legal
    // revoke target), so a rollback-to-0 probe is a 400 request-shape rejection —
    // the spec's stale-epoch 409 needs target >= 1 and is exercised in H8.
    const revokeRollback = await callGate("POST", "/revoke", {
      docId,
      idHash: voucherTwo.idHash,
      ownerUcan: await mintAdminUcan(docId),
      epoch: 0,
    });
    // Status-only: epoch 0 fails Joi's epoch>=1 rule (revoke validation), so the
    // 400 body carries a Joi-generated ValidationError message, not a fixed
    // string — there is no stable message to pin here.
    ensureReply(h7, "epoch-0 rollback rejected", revokeRollback, 400);
    console.log("H7 revoke replay 204; epoch-0 rollback rejected 400 ... ok");

    // ================= H8: never-enrolled revoke + stale epoch =================
    const h8 = "H8";
    const ghostVoucher = await mintVoucher(docId, "ghost@example.com");
    const ghostRevoke = await callGate("POST", "/revoke", {
      docId,
      idHash: ghostVoucher.idHash,
      ownerUcan: await mintAdminUcan(docId),
      epoch: 2,
    });
    ensureReply(h8, "never-enrolled revoke (lockout prevention)", ghostRevoke, 204);
    ensure(h8, "membership unchanged", (await fetchGroup(h8, docId)).members.includes(memberOneCommitment));
    const releaseAtTwo = await releaseAs(h8, memberOne, docId);
    ensureReply(h8, "release at epoch 2", releaseAtTwo, 200);
    const epochTwoShare = (releaseAtTwo.body?.shares as { view: string })?.view;
    // Presence first — a missing/renamed key must fail loudly, not satisfy `undefined !== x`.
    ensure(h8, "epoch-2 view share decodes to 32 bytes", Buffer.from(epochTwoShare ?? "", "base64").length === 32);
    ensure(
      h8,
      "release now serves the epoch-2 share (≠ epoch-1)",
      epochTwoShare !== ownerShare1,
      "gateShare bytes identical to epoch-1"
    );
    // Forward-only check at a now-reachable stale target (current epoch is 2).
    const staleRevoke = await callGate("POST", "/revoke", {
      docId,
      idHash: ghostVoucher.idHash,
      ownerUcan: await mintAdminUcan(docId),
      epoch: 1,
    });
    // 409 message pinned (exact throw text of revokeMember — src/interface/gate/revoke.ts).
    // The current epoch is 2 here (the ghost revoke at H8 advanced it to 2), and
    // this stale probe targets epoch 1 → the message is templated with both. This
    // distinguishes the stale-EPOCH 409 from the stale-ROOT (H6) and anchor (H11) 409s.
    ensureReply(
      h8,
      "stale target epoch behind current",
      staleRevoke,
      409,
      "STALE_EPOCH"
    );
    console.log("H8 ghost revoke advances epoch; stale target epoch 409 ... ok");

    // ================= H9: nonce single-use + cross-doc =================
    const h9 = "H9";
    const reusedNonce = await mintChallenge(h9, docId);
    const liveMembers = (await fetchGroup(h9, docId)).members;
    const reuseProof = await generateProof(memberOne, new Group(liveMembers.map(BigInt)), reusedNonce, docId);
    const firstUse = await callGate("POST", "/release", { docId, proof: reuseProof });
    const secondUse = await callGate("POST", "/release", { docId, proof: reuseProof });
    ensureReply(h9, "first use", firstUse, 200);
    // 403 message pinned (exact throw text — src/interface/gate/release.ts): a
    // burnt single-use nonce fails the live-nonce match, distinct from the scope
    // (H13), BIND (H4) and owner (H12) 403s that share this status.
    ensureReply(h9, "replayed nonce", secondUse, 403, "NONCE_NOT_LIVE");

    // register docB so it can issue nonces; a docB nonce must not release docA
    const registerB = await callGate("POST", "/register", {
      docId: docIdB,
      acceptedRoots: [{ groupRef: docIdB, role: "view" }],
      ownerUcan: await mintAdminUcan(docIdB),
      anchorRef: { ...anchorRef, fileId: 8 },
    });
    ensureReply(h9, "register docB", registerB, 200);
    const crossProof = await generateProof(
      memberOne,
      new Group(liveMembers.map(BigInt)),
      await mintChallenge(h9, docIdB), // docB's nonce — live, but minted for the other doc
      docId
    );
    const crossUse = await callGate("POST", "/release", { docId, proof: crossProof });
    // Same live-nonce-match 403: a docB-minted nonce is not live for docA's
    // per-doc nonce set, so it fails the match exactly like a replayed nonce.
    ensureReply(h9, "cross-doc nonce", crossUse, 403, "NONCE_NOT_LIVE");
    console.log("H9 nonce single-use 403 on replay; cross-doc nonce 403 ... ok");

    // ================= H11: register idempotency vs anchor pin =================
    const h11 = "H11";
    const reRegister = await callGate("POST", "/register", {
      docId,
      acceptedRoots: [{ groupRef: docId, role: "view" }],
      ownerUcan: await mintAdminUcan(docId),
      anchorRef,
    });
    ensureReply(h11, "re-register same anchor", reRegister, 200);
    ensure(
      h11,
      "re-register reports the LIVE epoch (2, not 0)",
      reRegister.body?.currentEpoch === 2,
      redactedBody(reRegister)
    );
    const survivedMembers = (await fetchGroup(h11, docId)).members;
    ensure(
      h11,
      "group survived re-register as exactly [memberOne]",
      survivedMembers.length === 1 && survivedMembers[0] === memberOneCommitment,
      `members=${JSON.stringify(survivedMembers)}` // commitments are public values
    );
    const squat = await callGate("POST", "/register", {
      docId,
      acceptedRoots: [{ groupRef: docId, role: "view" }],
      ownerUcan: await mintAdminUcan(docId),
      anchorRef: { ...anchorRef, fileId: 999 },
    });
    // 409 message pinned (exact throw text — src/interface/gate/register.ts):
    // distinguishes register's anchor-conflict 409 from the stale-root (H6) and
    // stale-epoch (H8) 409s.
    ensureReply(
      h11,
      "different-anchor re-register",
      squat,
      409,
      "ANCHOR_MISMATCH"
    );
    console.log("H11 re-register preserves state; different anchor 409 ... ok");

    // ================= H12: non-owner UCAN =================
    const h12 = "H12";
    const intruderShare = await callGate("POST", "/share", {
      docId,
      epoch: 0,
      ownerUcan: await mintAdminUcan(docId, intruderKeypair), // well-formed self-audience, wrong owner
    });
    // The intruder UCAN is well-formed and self-audience with the gate/ADMIN cap,
    // so it passes shape/audience/capability and reaches the on-chain owner
    // cross-check, where its DID != the (dev-override) owner DID. 403 message
    // pinned (exact throw text via assertIssuerIsOnChainOwner —
    // src/domain/gate/owner-auth.ts) to prove the rejection is the OWNER check,
    // not an upstream UCAN-shape 401/403.
    ensureReply(
      h12,
      "intruder share",
      intruderShare,
      403,
      "NOT_DOC_OWNER"
    );
    console.log("H12 non-owner admin UCAN 403 ... ok");

    // ================= H13: scope mismatch =================
    const h13 = "H13";
    // The challenge is minted from DOCB on purpose: the proof's ONLY defect is
    // then its scope (docA), so the asserted rejection can come from nothing
    // but the scope check. The nonce IS live for docB — if /release's scope
    // check ever regressed, this request would proceed to nonce-consume and
    // then fail the root check with 409 STALE_GROUP_ROOT (docB's group is empty),
    // or even 200 if the roots coincided; either flips the asserted 403 and fails
    // the harness. A docA-issued nonce could not provide that protection: the nonce
    // check would reject with the IDENTICAL {403, NONCE_NOT_LIVE}, masking a
    // scope-check regression.
    const scopedProof = await generateProof(
      memberOne, // docA member
      new Group((await fetchGroup(h13, docId)).members.map(BigInt)), // docA's live group
      await mintChallenge(h13, docIdB), // message = docB's LIVE nonce
      docId // scope = docA — the single thing wrong with this request
    );
    const wrongDoc = await callGate("POST", "/release", { docId: docIdB, proof: scopedProof });
    // CRITICAL regression-proofing: pin the EXACT scope code so a scope-check
    // regression that fell through to the nonce check (which would ALSO 403, with
    // NONCE_NOT_LIVE) cannot pass spuriously. The docB-live nonce above is the
    // other half of this guard. (PROOF_SCOPE_MISMATCH from assertProofScope —
    // src/domain/gate/proof-verification.ts)
    ensureReply(h13, "docA-scoped proof against docB", wrongDoc, 403, "PROOF_SCOPE_MISMATCH");
    console.log("H13 cross-doc proof scope 403 (scope check specifically, via a docB-live nonce) ... ok");

    // ================= H14: group register → group-enroll → GET /group/:ref =================
    const h14 = "H14";
    const groupId = `g-${runTag}`; // shortUUID-shaped; well under the 31-byte groupRef ceiling
    const groupAnchor = { ...anchorRef, fileId: 0 }; // groups carry fileId=0 (unused; portal-owner auth)

    const groupRegister = await callGate("POST", "/group/register", {
      groupRef: groupId,
      anchorRef: groupAnchor,
      ownerUcan: await mintGroupAdminUcan(groupId),
    });
    ensureReply(h14, "group register", groupRegister, 200);
    ensure(h14, "group register ok:true", groupRegister.body?.ok === true, redactedBody(groupRegister));

    const groupVoucherOne = await mintGroupVoucher(groupId, memberOneEmail);
    const groupEnrollOne = await callGate("POST", `/group/${groupId}/enroll`, {
      voucher: groupVoucherOne.token,
      commitment: memberOneCommitment,
      privyIdToken: await mintPrivyToken([memberOneEmail]),
    });
    ensureReply(h14, "group enroll member one", groupEnrollOne, 204);

    const groupAfterEnroll = await fetchGateGroup(h14, groupId);
    ensure(
      h14,
      "group read-after-write is exactly [memberOne]",
      groupAfterEnroll.members.length === 1 && groupAfterEnroll.members[0] === memberOneCommitment,
      `members=${JSON.stringify(groupAfterEnroll.members)}`
    );
    ensure(
      h14,
      "group root matches local LeanIMT",
      groupAfterEnroll.root === new Group(groupAfterEnroll.members.map(BigInt)).root.toString()
    );

    // Task 1.7 loosened register guard: a doc may register an acceptedRoots entry for a
    // PREVIOUSLY-REGISTERED named group (groupRef !== docId), but a non-existent group
    // ref is rejected 400. (Exercises register.ts's nonSelfRefs getGateGroup loop.)
    const docRefGroup = `dr-${runTag}`;
    const registerWithGroupRoot = await callGate("POST", "/register", {
      docId: docRefGroup,
      acceptedRoots: [
        { groupRef: docRefGroup, role: "view" }, // own implicit group
        { groupRef: groupId, role: "view" }, // the existing named group — must be allowed
      ],
      ownerUcan: await mintAdminUcan(docRefGroup),
      anchorRef: { ...anchorRef, fileId: 31 },
    });
    ensureReply(h14, "register doc referencing an existing group root", registerWithGroupRoot, 200);

    const registerWithBogusGroup = await callGate("POST", "/register", {
      docId: `db-${runTag}`,
      acceptedRoots: [{ groupRef: `nope-${runTag}`, role: "view" }], // unregistered group ref
      ownerUcan: await mintAdminUcan(`db-${runTag}`),
      anchorRef: { ...anchorRef, fileId: 32 },
    });
    // 400 message pinned (register.ts nonSelfRefs guard): a doc cannot accept a root for
    // a group the gate has never registered.
    ensureReply(h14, "register doc referencing an unknown group root", registerWithBogusGroup, 400, "INVALID_ACCEPTED_ROOTS");
    console.log("H14 group register/enroll/GET — commitment + root; loosened register guard ... ok");

    // ================= H15: attach group to a doc → member releases via GROUP root =================
    // Full §9.4 path: owner wraps a fileKey under the epoch-0 share; the group member
    // (NOT in the doc's own members) recovers the SAME fileKey bytes via the group root.
    const h15 = "H15";
    const docG = `dg-${runTag}`; // group-attached doc
    const docGAnchor = { ...anchorRef, fileId: 21 };

    const registerDocG = await callGate("POST", "/register", {
      docId: docG,
      acceptedRoots: [{ groupRef: docG, role: "view" }], // own implicit group only (empty for now)
      ownerUcan: await mintAdminUcan(docG),
      anchorRef: docGAnchor,
    });
    ensureReply(h15, "register docG", registerDocG, 200);

    // Owner wraps the fileKey under the epoch-0 share (the doc-creation wrap, §9.4).
    const shareDocG0 = await callGate("POST", "/share", {
      docId: docG,
      epoch: 0,
      ownerUcan: await mintAdminUcan(docG),
    });
    ensureReply(h15, "owner share docG epoch 0", shareDocG0, 200);
    const ownerShareDocG0 = (shareDocG0.body?.shares as { view: string })?.view;
    const docGFileKey = randomBytes(32);
    const docGWrappedFileKey = await wrapWithKey(docGFileKey, deriveWrapKeyBytes(seed, ownerShareDocG0, salt));

    // Attach the group to docG (doc owner authorizes; cross-portal OK — same portal).
    const attachG = await callGate("POST", `/doc/${docG}/attach`, {
      groupRef: groupId,
      role: "view",
      ownerUcan: await mintAdminUcan(docG),
    });
    ensureReply(h15, "attach group to docG", attachG, 204);

    // The group member proves the GROUP root, scope=docG → /release.
    const groupReleaseG = await releaseViaGroup(h15, memberOne, docG, groupId);
    ensureReply(h15, "group member releases via group root", groupReleaseG, 200);
    const groupMemberShareG = (groupReleaseG.body?.shares as { view: string })?.view;
    ensure(
      h15,
      "CORE Option A: group-release share === owner epoch-0 share",
      groupMemberShareG === ownerShareDocG0,
      "gateShare bytes mismatch (Option A violated)"
    );
    // The §9.4 keystone: the group member recovers the SAME fileKey bytes the owner wrapped.
    const docGUnwrapped = await unwrapWithKey(docGWrappedFileKey, deriveWrapKeyBytes(seed, groupMemberShareG, salt));
    ensure(
      h15,
      "CORE group member recovers the owner-wrapped fileKey bytes",
      !!docGUnwrapped && Buffer.from(docGUnwrapped).equals(docGFileKey),
      "group-side fileKey unwrap failed"
    );
    console.log("H15 attach + group-root release recovers the doc's fileKey (full §9.4 path) ... ok");

    // ================= H16: union — individual proof AND group proof unwrap the SAME fileKey =====
    const h16 = "H16";
    const docU = `du-${runTag}`; // doc with BOTH an individual member and an attached group
    const docUAnchor = { ...anchorRef, fileId: 22 };

    const registerDocU = await callGate("POST", "/register", {
      docId: docU,
      acceptedRoots: [{ groupRef: docU, role: "view" }],
      ownerUcan: await mintAdminUcan(docU),
      anchorRef: docUAnchor,
    });
    ensureReply(h16, "register docU", registerDocU, 200);

    // Owner wraps the fileKey under docU's epoch-0 share.
    const shareDocU0 = await callGate("POST", "/share", {
      docId: docU,
      epoch: 0,
      ownerUcan: await mintAdminUcan(docU),
    });
    ensureReply(h16, "owner share docU epoch 0", shareDocU0, 200);
    const ownerShareDocU0 = (shareDocU0.body?.shares as { view: string })?.view;
    const docUFileKey = randomBytes(32);
    const docUWrappedFileKey = await wrapWithKey(docUFileKey, deriveWrapKeyBytes(seed, ownerShareDocU0, salt));

    // Individual member (memberTwo) enrolls into docU's OWN implicit group via a
    // DOC-scoped voucher (the individuals path — distinct root from the group root).
    const docUIndividualVoucher = await mintVoucher(docU, outsiderEmail);
    const docUEnroll = await callGate("POST", "/enroll", {
      docId: docU,
      voucher: docUIndividualVoucher.token,
      commitment: memberTwoCommitment,
      privyIdToken: await mintPrivyToken([outsiderEmail]),
    });
    ensureReply(h16, "enroll individual into docU implicit group", docUEnroll, 204);

    // Attach the named group (its root holds memberOne — a DIFFERENT non-"0" root).
    const attachU = await callGate("POST", `/doc/${docU}/attach`, {
      groupRef: groupId,
      role: "view",
      ownerUcan: await mintAdminUcan(docU),
    });
    ensureReply(h16, "attach group to docU", attachU, 204);

    // Sanity: the union now has TWO distinct non-"0" roots (implicit vs group).
    const docUImplicitRoot = (await fetchGroup(h16, docU)).root;
    const docUGroupRoot = (await fetchGateGroup(h16, groupId)).root;
    ensure(
      h16,
      "union has two distinct non-zero roots",
      docUImplicitRoot !== "0" && docUGroupRoot !== "0" && docUImplicitRoot !== docUGroupRoot,
      `implicit=${docUImplicitRoot} group=${docUGroupRoot}`
    );

    // Individual proof (docU's own members) releases.
    const individualReleaseU = await releaseAs(h16, memberTwo, docU);
    ensureReply(h16, "individual proof releases", individualReleaseU, 200);
    const individualShareU = (individualReleaseU.body?.shares as { view: string })?.view;

    // Group proof (the named group's members) releases.
    const groupReleaseU = await releaseViaGroup(h16, memberOne, docU, groupId);
    ensureReply(h16, "group proof releases", groupReleaseU, 200);
    const groupShareU = (groupReleaseU.body?.shares as { view: string })?.view;

    // Option A: both doors return the IDENTICAL share, and both unwrap the SAME fileKey.
    ensure(
      h16,
      "CORE individual share === group share (Option A)",
      individualShareU === groupShareU && individualShareU === ownerShareDocU0,
      "shares diverge across audiences"
    );
    const unwrapViaIndividual = await unwrapWithKey(docUWrappedFileKey, deriveWrapKeyBytes(seed, individualShareU, salt));
    const unwrapViaGroup = await unwrapWithKey(docUWrappedFileKey, deriveWrapKeyBytes(seed, groupShareU, salt));
    ensure(
      h16,
      "CORE both audiences unwrap the identical fileKey",
      !!unwrapViaIndividual &&
        !!unwrapViaGroup &&
        Buffer.from(unwrapViaIndividual).equals(docUFileKey) &&
        Buffer.from(unwrapViaGroup).equals(docUFileKey),
      "individual/group unwrap disagree"
    );
    console.log("H16 union: individual + group proofs unwrap the identical fileKey ... ok");

    // ================= H17: group-revoke → removed member 409, survivor still releases =====
    const h17 = "H17";
    // Enroll memberTwo into the GROUP so we have a survivor after revoking memberOne.
    const groupVoucherTwo = await mintGroupVoucher(groupId, memberTwoEmail);
    const groupEnrollTwo = await callGate("POST", `/group/${groupId}/enroll`, {
      voucher: groupVoucherTwo.token,
      commitment: memberTwoCommitment,
      privyIdToken: await mintPrivyToken([memberTwoEmail]),
    });
    ensureReply(h17, "group enroll member two", groupEnrollTwo, 204);

    const preRevokeGroupMembers = (await fetchGateGroup(h17, groupId)).members; // [one, two]
    const groupRevokeOne = await callGate("POST", `/group/${groupId}/revoke`, {
      idHash: groupVoucherOne.idHash,
      ownerUcan: await mintGroupAdminUcan(groupId),
    });
    ensureReply(h17, "group revoke member one", groupRevokeOne, 204);
    ensure(
      h17,
      "member one evicted from group",
      !(await fetchGateGroup(h17, groupId)).members.includes(memberOneCommitment)
    );

    // Removed member proving the OLD (pre-revoke) group root against docG → stale 409.
    const staleGroupProof = await releaseViaGroup(h17, memberOne, docG, groupId, preRevokeGroupMembers);
    ensureReply(h17, "removed member's pre-revoke-root group proof", staleGroupProof, 409, "STALE_GROUP_ROOT");

    // Survivor (memberTwo) rebuilds against the CURRENT group root and still releases docG.
    const survivorGroupRelease = await releaseViaGroup(h17, memberTwo, docG, groupId);
    ensureReply(h17, "surviving group member still releases", survivorGroupRelease, 200);
    console.log("H17 group revoke: removed member stale-root 409; survivor releases (no epoch) ... ok");

    // ================= H18: detach → the group member's proof 409 (root not in accepted set) ===
    const h18 = "H18";
    const detachG = await callGate("POST", `/doc/${docG}/detach`, {
      groupRef: groupId,
      ownerUcan: await mintAdminUcan(docG),
    });
    ensureReply(h18, "detach group from docG", detachG, 204);

    // The surviving group member's CURRENT-root proof now 409s: docG's accepted set no
    // longer contains the group root (only docG's own — empty — implicit group remains).
    const postDetachProof = await releaseViaGroup(h18, memberTwo, docG, groupId);
    ensureReply(h18, "group proof after detach", postDetachProof, 409, "STALE_GROUP_ROOT");
    console.log("H18 detach: group root no longer in the doc's accepted set → 409 ... ok");

    // ================= H19: cross-portal attach (group portal X, doc portal Y) → 403 =====
    const h19 = "H19";
    const foreignGroupId = `gf-${runTag}`;
    const foreignAnchor = {
      chainId: anchorRef.chainId,
      portalAddress: `0x${randomBytes(20).toString("hex")}`, // DIFFERENT portal
      fileId: 0,
    };
    const foreignGroupRegister = await callGate("POST", "/group/register", {
      groupRef: foreignGroupId,
      anchorRef: foreignAnchor,
      ownerUcan: await mintGroupAdminUcan(foreignGroupId),
    });
    ensureReply(h19, "register foreign-portal group", foreignGroupRegister, 200);

    // docG lives on docGAnchor's portal (== anchorRef.portalAddress); the foreign group
    // lives on a different portal → attach must 403.
    const crossPortalAttach = await callGate("POST", `/doc/${docG}/attach`, {
      groupRef: foreignGroupId,
      role: "view",
      ownerUcan: await mintAdminUcan(docG),
    });
    ensureReply(h19, "cross-portal attach", crossPortalAttach, 403, "CROSS_PORTAL_ATTACH");
    console.log("H19 cross-portal attach (group portal != doc portal) 403 ... ok");

    // ================= H20: group-enroll BIND mismatch + wrong-groupRef voucher → 403 =====
    const h20 = "H20";
    // BIND mismatch: voucher idHash is for an outsider, Privy attests memberOne.
    const groupBindVoucher = await mintGroupVoucher(groupId, "group-outsider@example.com");
    const groupBindFail = await callGate("POST", `/group/${groupId}/enroll`, {
      voucher: groupBindVoucher.token,
      commitment: new Identity(`harness-group-outsider-${runTag}`).commitment.toString(),
      privyIdToken: await mintPrivyToken([memberOneEmail]),
    });
    ensureReply(h20, "group enroll BIND mismatch", groupBindFail, 403, "BIND_MISMATCH");

    // Wrong-groupRef voucher: a voucher minted for the FOREIGN group presented to THIS
    // group. Its UCAN hierPart is foreignGroupId, so it fails the gate/INVITE capability
    // check on this groupRef (MISSING_CAPABILITY) — status 403 (message not over-pinned).
    const wrongGroupVoucher = await mintGroupVoucher(foreignGroupId, memberOneEmail);
    const wrongGroupRefFail = await callGate("POST", `/group/${groupId}/enroll`, {
      voucher: wrongGroupVoucher.token,
      commitment: memberOneCommitment,
      privyIdToken: await mintPrivyToken([memberOneEmail]),
    });
    ensureReply(h20, "wrong-groupRef voucher", wrongGroupRefFail, 403);
    console.log("H20 group enroll BIND mismatch 403; wrong-groupRef voucher 403 ... ok");

    // ============ H21: cross-portal /register acceptedRoots (group portal != doc portal) → 403 ====
    // Mirrors H19 (the /attach route) for the /register route: a new doc on the LOCAL portal
    // cannot register an acceptedRoots entry for the foreign-portal group from H19. The
    // register guard fires (pre-owner-auth) → 403 CROSS_PORTAL_ATTACH.
    const h21 = "H21";
    const docXP = `dxp-${runTag}`; // local-portal doc attempting a cross-portal root
    const crossPortalRegister = await callGate("POST", "/register", {
      docId: docXP,
      acceptedRoots: [
        { groupRef: docXP, role: "view" }, // own implicit group (always allowed)
        { groupRef: foreignGroupId, role: "view" }, // foreign-portal group → reject
      ],
      anchorRef, // LOCAL portal (foreignGroupId lives on a different portal)
      ownerUcan: await mintAdminUcan(docXP),
    });
    ensureReply(h21, "cross-portal register acceptedRoots", crossPortalRegister, 403, "CROSS_PORTAL_ATTACH");
    console.log("H21 cross-portal register acceptedRoots (group portal != doc portal) 403 ... ok");

    // ================= H22: owner /share returns DISTINCT per-role shares =================
    const h22 = "H22";
    const h22Share = await callGate("POST", "/share", {
      docId,
      epoch: 0,
      ownerUcan: await mintAdminUcan(docId),
    });
    ensureReply(h22, "owner share (role bundle)", h22Share, 200);
    const h22Shares = h22Share.body?.shares as { view: string; comment: string };
    ensure(
      h22,
      "view and comment shares differ (role byte in the PRF)",
      typeof h22Shares?.view === "string" && h22Shares.view !== h22Shares.comment
    );
    ensure(
      h22,
      "both role shares decode to 32 bytes",
      Buffer.from(h22Shares?.view ?? "", "base64").length === 32 &&
        Buffer.from(h22Shares?.comment ?? "", "base64").length === 32
    );
    console.log("H22 owner /share returns distinct view/comment shares ... ok");

    // ================= H23: per-role cryptographic boundary (view ≠ comment access) =======
    // A view member unwraps fileKey but can NEVER obtain the comment share to unwrap
    // commentKey; a comment member unwraps BOTH. This is the v2 boundary (the keystone).
    const h23 = "H23";
    const docR = `rd-${runTag}`;
    const anchorR = { ...anchorRef, fileId: 41 }; // fileId unused elsewhere
    const registerR = await callGate("POST", "/register", {
      docId: docR,
      acceptedRoots: [
        { groupRef: docR, role: "view" },
        { groupRef: docR, role: "comment" },
      ],
      ownerUcan: await mintAdminUcan(docR),
      anchorRef: anchorR,
    });
    ensureReply(h23, "register role doc", registerR, 200);

    const ownerR = (
      await callGate("POST", "/share", { docId: docR, epoch: 0, ownerUcan: await mintAdminUcan(docR) })
    ).body?.shares as { view: string; comment: string };

    const h23FileKey = randomBytes(32);
    const h23CommentKey = randomBytes(32);
    const h23WrappedFile = await wrapWithKey(h23FileKey, deriveWrapKeyBytes(seed, ownerR.view, salt));
    const h23WrappedComment = await wrapWithKey(h23CommentKey, deriveWrapKeyBytes(seed, ownerR.comment, salt));

    const vId = new Identity(`harness-view-member-${runTag}`);
    const vVoucher = await mintVoucher(docR, "view-member@example.com", "view");
    ensureReply(
      h23,
      "enroll view member",
      await callGate("POST", "/enroll", {
        docId: docR,
        voucher: vVoucher.token,
        commitment: vId.commitment.toString(),
        privyIdToken: await mintPrivyToken(["view-member@example.com"]),
      }),
      204
    );

    const cId = new Identity(`harness-comment-member-${runTag}`);
    const cVoucher = await mintVoucher(docR, "comment-member@example.com", "comment");
    ensureReply(
      h23,
      "enroll comment member",
      await callGate("POST", "/enroll", {
        docId: docR,
        voucher: cVoucher.token,
        commitment: cId.commitment.toString(),
        privyIdToken: await mintPrivyToken(["comment-member@example.com"]),
      }),
      204
    );

    const vRel = await releaseAs(h23, vId, docR);
    ensureReply(h23, "view member releases", vRel, 200);
    const vShares = vRel.body?.shares as { view: string; comment?: string };
    const cRel = await releaseAs(h23, cId, docR);
    ensureReply(h23, "comment member releases", cRel, 200);
    const cShares = cRel.body?.shares as { view: string; comment?: string };

    ensure(
      h23,
      "view member gets the view share and NO comment share",
      vShares.view === ownerR.view && vShares.comment === undefined
    );
    ensure(
      h23,
      "comment member gets BOTH shares",
      cShares.view === ownerR.view && cShares.comment === ownerR.comment
    );

    const vFile = await unwrapWithKey(h23WrappedFile, deriveWrapKeyBytes(seed, vShares.view, salt));
    ensure(h23, "view member unwraps fileKey", !!vFile && Buffer.from(vFile).equals(h23FileKey));
    ensure(h23, "view member has no comment share to unwrap commentKey", vShares.comment === undefined);

    const cFile = await unwrapWithKey(h23WrappedFile, deriveWrapKeyBytes(seed, cShares.view, salt));
    const cComment = await unwrapWithKey(
      h23WrappedComment,
      deriveWrapKeyBytes(seed, cShares.comment as string, salt)
    );
    ensure(
      h23,
      "comment member unwraps fileKey AND commentKey",
      !!cFile &&
        Buffer.from(cFile).equals(h23FileKey) &&
        !!cComment &&
        Buffer.from(cComment).equals(h23CommentKey)
    );
    console.log("H23 per-role boundary: view unwraps fileKey only, comment unwraps both ... ok");

    // ================= H24: enroll role-relabel (tier-switch primitive) ===================
    // Re-enrolling the SAME identity with a different-role voucher relabels its binding,
    // moving it between the view/comment sets — the gate primitive powering changeTier.
    const h24 = "H24";
    const docT = `td-${runTag}`;
    const anchorT = { ...anchorRef, fileId: 42 }; // fileId unused elsewhere
    ensureReply(
      h24,
      "register tier doc",
      await callGate("POST", "/register", {
        docId: docT,
        acceptedRoots: [
          { groupRef: docT, role: "view" },
          { groupRef: docT, role: "comment" },
        ],
        ownerUcan: await mintAdminUcan(docT),
        anchorRef: anchorT,
      }),
      200
    );

    const tId = new Identity(`harness-tier-member-${runTag}`);
    const tEmail = "tier-member@example.com";
    ensureReply(
      h24,
      "enroll as view",
      await callGate("POST", "/enroll", {
        docId: docT,
        voucher: (await mintVoucher(docT, tEmail, "view")).token,
        commitment: tId.commitment.toString(),
        privyIdToken: await mintPrivyToken([tEmail]),
      }),
      204
    );
    let tShares = (await releaseAs(h24, tId, docT)).body?.shares as { view: string; comment?: string };
    ensure(h24, "view-bound member gets no comment share", tShares.comment === undefined);

    ensureReply(
      h24,
      "re-enroll relabels view → comment",
      await callGate("POST", "/enroll", {
        docId: docT,
        voucher: (await mintVoucher(docT, tEmail, "comment")).token,
        commitment: tId.commitment.toString(),
        privyIdToken: await mintPrivyToken([tEmail]),
      }),
      204
    );
    tShares = (await releaseAs(h24, tId, docT)).body?.shares as { view: string; comment?: string };
    ensure(h24, "relabeled member now gets the comment share", tShares.comment !== undefined);

    ensureReply(
      h24,
      "re-enroll relabels comment → view",
      await callGate("POST", "/enroll", {
        docId: docT,
        voucher: (await mintVoucher(docT, tEmail, "view")).token,
        commitment: tId.commitment.toString(),
        privyIdToken: await mintPrivyToken([tEmail]),
      }),
      204
    );
    tShares = (await releaseAs(h24, tId, docT)).body?.shares as { view: string; comment?: string };
    ensure(h24, "downgraded member: comment share gone", tShares.comment === undefined);
    console.log("H24 enroll role-relabel (tier-switch primitive) ... ok");

    // ================= H25: group DELETE hard-revokes across ALL attached docs ============
    // deleteGroup removes the gate group row → resolveAcceptedRoots skips it for EVERY doc
    // that attached it, so one delete revokes the group's access everywhere (no per-doc
    // fan-out). Also proves the gate-side fall-through the reader relies on: a doc carrying
    // BOTH the deleted group AND a live root keeps granting via the live root.
    const h25 = "H25";
    const delGroupId = `gd25-${runTag}`;
    ensureReply(
      h25,
      "register delete-group",
      await callGate("POST", "/group/register", {
        groupRef: delGroupId,
        anchorRef: { chainId: anchorRef.chainId, portalAddress: anchorRef.portalAddress, fileId: 0 },
        ownerUcan: await mintGroupAdminUcan(delGroupId),
      }),
      200
    );
    ensureReply(
      h25,
      "enroll member one into delete-group",
      await callGate("POST", `/group/${delGroupId}/enroll`, {
        voucher: (await mintGroupVoucher(delGroupId, memberOneEmail)).token,
        commitment: memberOneCommitment,
        privyIdToken: await mintPrivyToken([memberOneEmail]),
      }),
      204
    );

    // Two docs on the SAME portal both attach the group; docB also gets its OWN
    // individual member (memberTwo) — a SECOND, live root for the fall-through check.
    const docA25 = `da25-${runTag}`;
    const docB25 = `db25-${runTag}`;
    ensureReply(h25, "register docA25", await callGate("POST", "/register", {
      docId: docA25,
      acceptedRoots: [{ groupRef: docA25, role: "view" }],
      ownerUcan: await mintAdminUcan(docA25),
      anchorRef: { ...anchorRef, fileId: 51 },
    }), 200);
    ensureReply(h25, "register docB25", await callGate("POST", "/register", {
      docId: docB25,
      acceptedRoots: [{ groupRef: docB25, role: "view" }],
      ownerUcan: await mintAdminUcan(docB25),
      anchorRef: { ...anchorRef, fileId: 52 },
    }), 200);
    ensureReply(h25, "attach group to docA25", await callGate("POST", `/doc/${docA25}/attach`, {
      groupRef: delGroupId, role: "view", ownerUcan: await mintAdminUcan(docA25),
    }), 204);
    ensureReply(h25, "attach group to docB25", await callGate("POST", `/doc/${docB25}/attach`, {
      groupRef: delGroupId, role: "view", ownerUcan: await mintAdminUcan(docB25),
    }), 204);
    ensureReply(h25, "enroll individual into docB25", await callGate("POST", "/enroll", {
      docId: docB25,
      voucher: (await mintVoucher(docB25, memberTwoEmail)).token,
      commitment: memberTwoCommitment,
      privyIdToken: await mintPrivyToken([memberTwoEmail]),
    }), 204);

    // Pre-delete sanity: the group member releases via the group root on BOTH docs.
    ensureReply(h25, "pre-delete: group member releases docA25",
      await releaseViaGroup(h25, memberOne, docA25, delGroupId), 200);
    ensureReply(h25, "pre-delete: group member releases docB25",
      await releaseViaGroup(h25, memberOne, docB25, delGroupId), 200);

    // Snapshot the group members NOW (post-delete fetchGateGroup 404s) so we can prove
    // the dead root afterwards exactly as a stale client / 5-min cache would.
    const delGroupMembers = (await fetchGateGroup(h25, delGroupId)).members;

    // DELETE the whole group (owner-authorized).
    ensureReply(h25, "delete group", await callGate("POST", `/group/${delGroupId}/delete`, {
      ownerUcan: await mintGroupAdminUcan(delGroupId),
    }), 204);
    // Pin the GET's 404 BODY CODE, not just the status: the client reader's PRIMARY
    // fall-through (group-reader.ts) keys on GateError.code === 'GROUP_NOT_REGISTERED'
    // from exactly this call, so a bare-404 regression here would silently break the
    // [deletedGroup, liveGroup] fall-through.
    ensureReply(h25, "deleted group GET 404 + code",
      await callGate("GET", `/group/${delGroupId}`), 404, "GROUP_NOT_REGISTERED");

    // HARD-REVOKE FAN-OUT: the group member's proof now 409s on BOTH docs — the deleted
    // group's root is no longer in either doc's accepted set, with no per-doc detach.
    ensureReply(h25, "post-delete: group proof 409 on docA25",
      await releaseViaGroup(h25, memberOne, docA25, delGroupId, delGroupMembers), 409, "STALE_GROUP_ROOT");
    ensureReply(h25, "post-delete: group proof 409 on docB25",
      await releaseViaGroup(h25, memberOne, docB25, delGroupId, delGroupMembers), 409, "STALE_GROUP_ROOT");

    // FALL-THROUGH (gate half of reader fault-isolation): docB25's individual member still
    // releases via the LIVE individual root while the deleted group's root 409s — a member
    // of [deletedGroup, liveRoot] keeps access.
    ensureReply(h25, "post-delete: individual still releases docB25",
      await releaseAs(h25, memberTwo, docB25), 200);

    // Idempotent re-delete: the row is already gone → 404 (the client treats as success).
    ensureReply(h25, "re-delete already-gone group 404",
      await callGate("POST", `/group/${delGroupId}/delete`, { ownerUcan: await mintGroupAdminUcan(delGroupId) }),
      404, "GROUP_NOT_REGISTERED");
    console.log("H25 group delete hard-revokes across all attached docs; live roots survive ... ok");

    // ================= H26: doc denylist + reinstate ==========================================
    // State entering H26: docId currentEpoch=2 (H6→1, H8→2). memberOne is enrolled and
    // NOT denylisted. memberTwo is already denylisted (H6 revoked it with addToDenylist:true).
    // So we revoke memberOne (epoch 3, denylist=true), prove the denylist 403 fires on its
    // still-valid voucher, reinstate it, then re-enroll successfully.
    const h26 = "H26";
    const h26RevokeEpoch = 3; // forward of currentEpoch=2
    const revokeOneH26 = await callGate("POST", "/revoke", {
      docId,
      idHash: voucherOne.idHash,
      ownerUcan: await mintAdminUcan(docId),
      epoch: h26RevokeEpoch,
      // addToDenylist omitted → defaults to true in revoke.ts (addToDenylist ?? true)
    });
    ensureReply(h26, "revoke memberOne (denylist)", revokeOneH26, 204);

    // memberOne's voucher is still cryptographically valid but idHash is now denylisted.
    const denylistEnrollH26 = await callGate("POST", "/enroll", {
      docId,
      voucher: voucherOne.token,
      commitment: memberOneCommitment,
      privyIdToken: await mintPrivyToken([memberOneEmail]),
    });
    // 403 IDENTITY_REVOKED: the denylist check fires before PIN+ADD.
    ensureReply(h26, "denylisted enroll → IDENTITY_REVOKED", denylistEnrollH26, 403, "IDENTITY_REVOKED");

    // Owner reinstates: $pull idHash from revokedIdHashes.
    const reinstateOneH26 = await callGate("POST", "/reinstate", {
      docId,
      idHash: voucherOne.idHash,
      ownerUcan: await mintAdminUcan(docId),
    });
    ensureReply(h26, "reinstate memberOne", reinstateOneH26, 204);

    // Re-enroll succeeds now that the idHash is off the denylist.
    // memberOne was evicted from members by the H26 revoke, so this is a fresh add.
    const reEnrollOneH26 = await callGate("POST", "/enroll", {
      docId,
      voucher: voucherOne.token,
      commitment: memberOneCommitment,
      privyIdToken: await mintPrivyToken([memberOneEmail]),
    });
    ensureReply(h26, "re-enroll after reinstate succeeds", reEnrollOneH26, 204);
    console.log("H26 doc denylist+reinstate: IDENTITY_REVOKED 403 lifted by /reinstate, re-enroll 204 ... ok");

    // ================= H27: group denylist + reinstate ========================================
    // State entering H27: groupId members = [memberTwo] (memberOne was evicted + denylisted
    // in H17). So we revoke memberTwo (groupVoucherTwo, always denylists), prove 403 on
    // group re-enroll, reinstate, re-enroll successfully.
    const h27 = "H27";
    const groupRevokeTwoH27 = await callGate("POST", `/group/${groupId}/revoke`, {
      idHash: groupVoucherTwo.idHash,
      ownerUcan: await mintGroupAdminUcan(groupId),
    });
    ensureReply(h27, "group revoke memberTwo (denylist)", groupRevokeTwoH27, 204);

    // memberTwo's group voucher is still valid but idHash is now on the group denylist.
    const denylistGroupEnrollH27 = await callGate("POST", `/group/${groupId}/enroll`, {
      voucher: groupVoucherTwo.token,
      commitment: memberTwoCommitment,
      privyIdToken: await mintPrivyToken([memberTwoEmail]),
    });
    // 403 IDENTITY_REVOKED: group enroll denylist check (group-enroll.ts).
    ensureReply(h27, "denylisted group enroll → IDENTITY_REVOKED", denylistGroupEnrollH27, 403, "IDENTITY_REVOKED");

    // Owner reinstates: $pull idHash from group revokedIdHashes.
    const reinstateGroupTwoH27 = await callGate("POST", `/group/${groupId}/reinstate`, {
      idHash: groupVoucherTwo.idHash,
      ownerUcan: await mintGroupAdminUcan(groupId),
    });
    ensureReply(h27, "group reinstate memberTwo", reinstateGroupTwoH27, 204);

    // Re-enroll into the group succeeds after reinstate.
    const reEnrollGroupTwoH27 = await callGate("POST", `/group/${groupId}/enroll`, {
      voucher: groupVoucherTwo.token,
      commitment: memberTwoCommitment,
      privyIdToken: await mintPrivyToken([memberTwoEmail]),
    });
    ensureReply(h27, "re-enroll into group after reinstate succeeds", reEnrollGroupTwoH27, 204);
    console.log("H27 group denylist+reinstate: IDENTITY_REVOKED 403 lifted by /reinstate, re-enroll 204 ... ok");

    // ================= H28: addToDenylist:false does NOT block future enroll =================
    // /revoke with addToDenylist:false is the mechanical epoch-bump path (changeTier
    // ghost-revoke). It must NOT add the idHash to the denylist. We prove this by:
    // 1. Revoking a sentinel idHash with addToDenylist:false (epoch 4, forward of epoch 3).
    // 2. Enrolling memberOne (reinstated in H26, currently valid on docId) → must NOT 403.
    // This proves the denylist remained untouched by the false-flag revoke.
    const h28 = "H28";
    const h28SentinelVoucher = await mintVoucher(docId, "h28-sentinel@example.com");
    const h28SentinelRevoke = await callGate("POST", "/revoke", {
      docId,
      idHash: h28SentinelVoucher.idHash,
      ownerUcan: await mintAdminUcan(docId),
      epoch: 4, // forward of h26RevokeEpoch=3
      addToDenylist: false,
    });
    ensureReply(h28, "sentinel revoke with addToDenylist:false", h28SentinelRevoke, 204);

    // Now enroll memberOne (valid, reinstated in H26, not in denylist): must NOT be 403.
    // memberOne was re-enrolled in H26 but epoch 4 may have advanced the epoch — that's fine
    // for enroll (enroll does not check epoch). The commitment pin (H5-style) holds across
    // epoch advances; re-enrolling the same (idHash, commitment) returns "noop" → 204.
    const h28ValidEnroll = await callGate("POST", "/enroll", {
      docId,
      voucher: voucherOne.token,
      commitment: memberOneCommitment,
      privyIdToken: await mintPrivyToken([memberOneEmail]),
    });
    ensure(
      h28,
      "addToDenylist:false did not block valid enroll (status !== 403)",
      h28ValidEnroll.status !== 403,
      `got status=${h28ValidEnroll.status} body=${redactedBody(h28ValidEnroll)}`
    );
    // Also confirm the sentinel itself is NOT blocked (no denylist entry was written).
    const h28SentinelEnroll = await callGate("POST", "/enroll", {
      docId,
      voucher: h28SentinelVoucher.token,
      commitment: new Identity(`harness-h28-sentinel-${runTag}`).commitment.toString(),
      privyIdToken: await mintPrivyToken(["h28-sentinel@example.com"]),
    });
    ensure(
      h28,
      "sentinel's own enroll is also not IDENTITY_REVOKED (addToDenylist:false left denylist clean)",
      h28SentinelEnroll.status !== 403,
      `got status=${h28SentinelEnroll.status} body=${redactedBody(h28SentinelEnroll)}`
    );
    console.log("H28 addToDenylist:false: mechanical epoch-bump leaves denylist untouched, valid enroll succeeds ... ok");

    console.log("\nALL 27 SCENARIOS PASSED");
  } finally {
    await stopGate();
    try {
      await dropHarnessDb();
      console.log(`throwaway db ${HARNESS_DB_NAME} dropped (post-run)`);
    } catch (cleanupError) {
      // Don't mask the original failure (e.g. mongod itself went away).
      console.error(`post-run drop of ${HARNESS_DB_NAME} failed:`, cleanupError);
    }
  }
};

void main()
  .then(() => process.exit(0))
  .catch((error) => {
    if (error instanceof CheckFailure) console.error(`\n${error.message}`);
    else console.error("\nharness crashed:", error);
    process.exit(1);
  });
