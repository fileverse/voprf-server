import { EvaluationRequest, VOPRFServer } from "@cloudflare/voprf-ts";
import { fromUint8Array, toUint8Array } from "js-base64";
import { deriveVaultKeyPair, getVaultKeyConfig, VAULT_SUITE } from "../../infra/vault-keys";
import { throwError } from "../../infra/error-handler";
import { GateErrorCode } from "../../infra/gate-errors";

const requireConfig = () => {
  const cfg = getVaultKeyConfig();
  if (!cfg) return throwError({ code: 503, message: GateErrorCode.VAULT_KEY_NOT_CONFIGURED });
  return cfg;
};

const seedFor = (version: number): Uint8Array => {
  const cfg = requireConfig();
  if (version === cfg.current.version) return cfg.current.seed;
  if (cfg.previous && version === cfg.previous.version) return cfg.previous.seed;
  return throwError({ code: 409, message: GateErrorCode.VAULT_KEY_VERSION_RETIRED });
};

export const getVaultPublicKey = async (
  identity: string,
  version?: number
): Promise<{ publicKey: string; keyVersion: number }> => {
  const cfg = requireConfig();
  const keyVersion = version ?? cfg.current.version;
  const { publicKey } = await deriveVaultKeyPair(seedFor(keyVersion), keyVersion, identity);
  return { publicKey: fromUint8Array(publicKey), keyVersion };
};

export const evaluateForIdentity = async (
  identity: string,
  evaluationRequest: string,
  keyVersion: number
): Promise<{
  evaluation: string;
  keyVersion: number;
  currentKeyVersion: number;
  currentPublicKey: string;
}> => {
  const cfg = requireConfig();
  const { privateKey } = await deriveVaultKeyPair(seedFor(keyVersion), keyVersion, identity);

  let request: EvaluationRequest;
  try {
    request = EvaluationRequest.deserialize(VAULT_SUITE, toUint8Array(evaluationRequest));
  } catch {
    return throwError({ code: 400, message: GateErrorCode.INVALID_EVALUATION_REQUEST });
  }
  // One element per call: a batch would let one authorized call key many seeds.
  if (request.blinded.length !== 1) {
    return throwError({ code: 400, message: GateErrorCode.INVALID_EVALUATION_REQUEST });
  }

  const evaluation = await new VOPRFServer(VAULT_SUITE, privateKey).blindEvaluate(request);
  const current = await getVaultPublicKey(identity, cfg.current.version);
  return {
    evaluation: fromUint8Array(evaluation.serialize()),
    keyVersion,
    currentKeyVersion: cfg.current.version,
    currentPublicKey: current.publicKey,
  };
};
