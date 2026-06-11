// Express async wrapper: forward a rejected promise to next(err) for the central handler.
import { RequestHandler } from "express";

export const asyncHandler =
  (fn: RequestHandler): RequestHandler =>
  (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

export const asyncHandlerArray = (handlers: RequestHandler[]): RequestHandler[] =>
  handlers.map(asyncHandler);
