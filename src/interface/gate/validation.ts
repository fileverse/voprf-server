// Gate-specific Joi field builders shared across the controller schemas. The
// commitment/proof canonical-decimal rule must AGREE between enroll and release,
// so both reuse the domain's isCanonicalDecimalBigInt rather than re-deriving it.
import { Joi } from "../middleware";
import { isCanonicalDecimalBigInt } from "../../domain/gate";
import { GateErrorCode } from "../../infra/gate-errors";

// docId is the Semaphore proof scope: the client's encoding rejects plain strings
// over 31 UTF-8 bytes, so a longer docId could register but never be opened.
const DOC_ID_MAX_UTF8_BYTES = 31;

/** Required docId string, ≤31 UTF-8 bytes (Semaphore scope encoding limit). */
export const docIdField = () =>
  Joi.string()
    .required()
    .custom((value: string, helpers) => {
      if (Buffer.byteLength(value, "utf8") > DOC_ID_MAX_UTF8_BYTES) {
        return helpers.message({ custom: GateErrorCode.INVALID_DOC_ID });
      }
      return value;
    });

// groupRef is the voucher UCAN hierPart; same ≤31-UTF-8-byte rule as docIdField (the
// client mints shortUUIDs, comfortably under the ceiling). The charset is restricted to
// the shortUUID alphabet (alphanumeric plus `_`/`-`) so a groupRef can never carry a `/`
// or other path/scope-breaking byte.
const GROUP_REF_MAX_UTF8_BYTES = 31;
const GROUP_REF_CHARSET = /^[A-Za-z0-9_-]+$/;

/** Required groupRef string, ≤31 UTF-8 bytes, shortUUID charset. */
export const groupRefField = () =>
  Joi.string()
    .required()
    .custom((value: string, helpers) => {
      if (Buffer.byteLength(value, "utf8") > GROUP_REF_MAX_UTF8_BYTES) {
        return helpers.message({ custom: GateErrorCode.INVALID_GROUP_REF });
      }
      if (!GROUP_REF_CHARSET.test(value)) {
        return helpers.message({ custom: GateErrorCode.INVALID_GROUP_REF });
      }
      return value;
    });

/** Required canonical-decimal bigint string — shares the domain rule with release. */
export const commitmentField = () =>
  Joi.string()
    .required()
    .custom((value: string, helpers) => {
      if (!isCanonicalDecimalBigInt(value)) {
        return helpers.message({ custom: GateErrorCode.INVALID_COMMITMENT });
      }
      return value;
    });
