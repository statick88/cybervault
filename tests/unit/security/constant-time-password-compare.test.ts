/**
 * RQ5 mutation test — R1 secret compare.
 *
 * The mutant: `verifyPassword` swapping `crypto.timingSafeEqual(hashBuf, storedBuf)`
 * for a byte-wise string compare (`hash === storedHash`). The swap is
 * extensionally equivalent — every input returns the same answer — so no
 * functional assertion can see it. What it removes is the CONSTANT-TIME
 * property: an early-exit comparison leaks the matching prefix length through
 * response latency, which is the timing side channel R1 exists to close.
 *
 * The assertion that pins it: `verifyPassword` must reach the comparison
 * through `crypto.timingSafeEqual`.
 *
 * WHY `jest.mock` AND NOT `jest.spyOn`: `crypto` is a Node core module and
 * `timingSafeEqual` is not a configurable property, so `spyOn` throws
 * `TypeError: Cannot redefine property` against BOTH the original and the
 * mutant — a failure for the wrong reason proves nothing. Wrapping the module
 * through a factory intercepts the call at the import boundary instead.
 *
 * Verified by reverting the mutant — this test goes red with the byte-wise
 * compare in place, green with the original.
 */

import { hashPassword, verifyPassword } from "@/infrastructure/api/auth";

const mockTimingSafeEqual = jest.fn(
  jest.requireActual<typeof import("crypto")>("crypto").timingSafeEqual,
);

jest.mock("crypto", () => ({
  ...jest.requireActual("crypto"),
  timingSafeEqual: (a: Buffer, b: Buffer) => mockTimingSafeEqual(a, b),
}));

describe("R1 — verifyPassword compares in constant time", () => {
  beforeEach(() => {
    mockTimingSafeEqual.mockClear();
  });

  it("delegates the comparison to crypto.timingSafeEqual", () => {
    const { hash, salt } = hashPassword("correct horse battery staple");

    expect(verifyPassword("correct horse battery staple", hash, salt)).toBe(true);
    expect(mockTimingSafeEqual).toHaveBeenCalledTimes(1);
  });

  it("refuses a wrong password while still comparing in constant time", () => {
    const { hash, salt } = hashPassword("correct horse battery staple");

    expect(verifyPassword("wrong password", hash, salt)).toBe(false);
    expect(mockTimingSafeEqual).toHaveBeenCalledTimes(1);
  });
});
