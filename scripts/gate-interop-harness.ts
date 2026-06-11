// gate-interop-harness.ts — plays the ddocs.new GP client byte-for-byte against
// a locally spawned gate (docs/gate-server-design.md §11, scenarios H1–H13; H10 retired with key versioning).
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

/** Diagnostic-safe body: gateShare values must never reach stdout. */
const redactedBody = (reply: GateReply): string =>
  JSON.stringify(
    reply.body && "gateShare" in reply.body ? { ...reply.body, gateShare: "<redacted>" } : reply.body
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

    const fetchGroup = async (
      scenario: string,
      forDocId: string
    ): Promise<{ root: string; members: string[] }> => {
      const reply = await callGate("GET", `/doc/${forDocId}/group`);
      ensure(scenario, `GET /doc/${forDocId}/group`, reply.status === 200, `got ${reply.status}`);
      return reply.body as unknown as { root: string; members: string[] };
    };

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

    /** Full member release flow (reader.ts §2–4): challenge → local LeanIMT → proof → /release. */
    const releaseAs = async (
      scenario: string,
      identity: Identity,
      forDocId: string,
      membersOverride?: string[]
    ): Promise<GateReply> => {
      const nonce = await mintChallenge(scenario, forDocId);
      const members = membersOverride ?? (await fetchGroup(scenario, forDocId)).members;
      const group = new Group(members.map(BigInt));
      const proof = await generateProof(identity, group, nonce, forDocId); // message=nonce, scope=docId
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
    const ownerShare0 = shareEpoch0.body?.gateShare as string;
    ensure(h1, "share gateShare decodes to 32 bytes", Buffer.from(ownerShare0 ?? "", "base64").length === 32);

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
    const memberShare0 = releaseOne.body?.gateShare as string;
    ensure(h1, "CORE share(0) === release bytes", ownerShare0 === memberShare0, "gateShare bytes mismatch");
    console.log("H1 register/share/enroll/group/release + gateShare byte-equality ... ok");

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
    const ownerShare1 = shareEpoch1.body?.gateShare as string;
    // Presence first — a missing/renamed key must fail loudly, not satisfy `undefined !== x`.
    ensure(h6, "epoch-1 gateShare decodes to 32 bytes", Buffer.from(ownerShare1 ?? "", "base64").length === 32);
    ensure(h6, "epoch-1 share differs from epoch-0", ownerShare1 !== ownerShare0, "gateShare bytes identical");

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
      survivorRelease.body?.gateShare === ownerShare1,
      "gateShare bytes mismatch vs owner's epoch-1 pull"
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
    const epochTwoShare = releaseAtTwo.body?.gateShare as string;
    // Presence first — a missing/renamed key must fail loudly, not satisfy `undefined !== x`.
    ensure(h8, "epoch-2 gateShare decodes to 32 bytes", Buffer.from(epochTwoShare ?? "", "base64").length === 32);
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

    console.log("\nALL 12 SCENARIOS PASSED");
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
