// Re-export of express-validation's validate + Joi (storage-v2 pattern). express-
// validation pins express-4 @types, so its validate() return type is structurally
// incompatible with this app's express-5 RequestHandler — we retype it here at the
// one re-export point so the controllers stay cast-free.
import { validate as evValidate, ValidationError, Joi } from "express-validation";
import type { RequestHandler } from "express";

const validate = (...args: Parameters<typeof evValidate>): RequestHandler =>
  evValidate(...args) as unknown as RequestHandler;

export { validate, Joi, ValidationError };
