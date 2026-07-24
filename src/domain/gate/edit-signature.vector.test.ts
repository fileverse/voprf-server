import { describe, it, expect } from "vitest";
import { Identity } from "@semaphore-protocol/identity";
import {
  editChallengeMessage,
  verifyEditSignatureAndDeriveCommitment,
  type EddsaSignature,
} from "./edit-signature";

/**
 * Phase 0 interop keystone. The editor signs the edit challenge in the browser
 * (ddocs.new signEditChallenge); this gate independently rebuilds the same challenge
 * and verifies it. The EXPECTED_* constants below are the cross-repo CONTRACT — the
 * client suite (ddocs.new/utils/private-access-scheme/semaphore/__tests__/
 * edit-signature.vector.test.ts) asserts the identical values. If either side's
 * string→field encoding, Poseidon arity, or field order drifts, one of the two suites
 * fails. EdDSA-Poseidon signing is deterministic, so a fixed seed + challenge
 * reproduces byte-for-byte here and there.
 *
 * To regenerate after an intentional encoding change: update BOTH repos' constants
 * together from the actual values a failing run prints.
 */
const DOC_ID = "doc-abc";
const NONCE = "nonce-123";

const EXPECTED_MSG =
  "16225299953522763491306409497875874781819986869270312632204870563134616112031";
const EXPECTED_COMMITMENT =
  "6370855036228342104654103720913400818499567268984300116178979531025657935460";
const EXPECTED_PUBLIC_KEY: [string, string] = [
  "21740709030497017962368109349317371152026420427867899159558025174250633557423",
  "21081842222554771852881092207295635439701081755461743063274813978670153358097",
];
const EXPECTED_SIGNATURE: EddsaSignature = {
  R8: [
    "21156240463793319182024697545388748740532096529048874442611923502713079695359",
    "5009542085386165230026953554081149947738041807656310861029679699689971392284",
  ],
  S: "2369844343222766004068441326216963916261438505621100365295237847081494121301",
};

describe("edit-signature interop vector (gate ↔ client)", () => {
  const identity = new Identity("test-seed");

  it("editChallengeMessage matches the cross-repo constant", () => {
    expect(editChallengeMessage(DOC_ID, NONCE).toString()).toBe(EXPECTED_MSG);
  });

  it("derives the expected commitment", () => {
    expect(Identity.generateCommitment(identity.publicKey).toString()).toBe(EXPECTED_COMMITMENT);
  });

  it("verifies the frozen client signature and derives the same commitment (cross-repo round-trip)", () => {
    const derived = verifyEditSignatureAndDeriveCommitment(
      DOC_ID,
      NONCE,
      EXPECTED_PUBLIC_KEY,
      EXPECTED_SIGNATURE
    );
    expect(derived).toBe(EXPECTED_COMMITMENT);
  });

  it("accepts a freshly-produced signature from the same identity", () => {
    const msg = editChallengeMessage(DOC_ID, NONCE);
    const sig = identity.signMessage(msg);
    const publicKey: [string, string] = [
      identity.publicKey[0].toString(),
      identity.publicKey[1].toString(),
    ];
    const signature: EddsaSignature = {
      R8: [sig.R8[0].toString(), sig.R8[1].toString()],
      S: sig.S.toString(),
    };
    expect(verifyEditSignatureAndDeriveCommitment(DOC_ID, NONCE, publicKey, signature)).toBe(
      EXPECTED_COMMITMENT
    );
  });

  it("rejects a tampered signature (returns null, never throws)", () => {
    const tampered: EddsaSignature = {
      ...EXPECTED_SIGNATURE,
      S: (BigInt(EXPECTED_SIGNATURE.S) + 1n).toString(),
    };
    expect(
      verifyEditSignatureAndDeriveCommitment(DOC_ID, NONCE, EXPECTED_PUBLIC_KEY, tampered)
    ).toBeNull();
  });

  it("rejects malformed (non-canonical) fields without throwing", () => {
    const malformed = { R8: ["not-a-bigint", "0"], S: "0" } as unknown as EddsaSignature;
    expect(
      verifyEditSignatureAndDeriveCommitment(DOC_ID, NONCE, EXPECTED_PUBLIC_KEY, malformed)
    ).toBeNull();
  });
});
