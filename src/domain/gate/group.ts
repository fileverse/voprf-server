import { Group } from "@semaphore-protocol/group";

/** Group root derived from members on every read, so it can't drift from the list. */
export const computeGroupRoot = (members: string[]): string =>
  members.length === 0 ? "0" : new Group(members.map(BigInt)).root.toString();
