import { beforeEach, describe, expect, it, vi } from "vitest";
import { getTokenMeta, parseJwt } from "./jwtUtils";

const tokenFor = (payload) => {
  const encoded = btoa(JSON.stringify(payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `header.${encoded}.signature`;
};

describe("jwtUtils", () => {
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  it("returns null for missing, non-string, malformed, and invalid tokens", () => {
    expect(parseJwt()).toBeNull();
    expect(parseJwt(123)).toBeNull();
    expect(parseJwt("not-a-jwt")).toBeNull();
    expect(parseJwt("a.invalid-json.c")).toBeNull();
  });

  it("parses token payloads and computes token metadata", () => {
    vi.spyOn(Date, "now").mockReturnValue(2_000);

    const token = tokenFor({ exp: 10, iat: 1, sub: "operator" });
    expect(parseJwt(token)).toEqual({ exp: 10, iat: 1, sub: "operator" });

    const meta = getTokenMeta(token);
    expect(meta.payload.sub).toBe("operator");
    expect(meta.expDate).toEqual(new Date(10_000));
    expect(meta.iatDate).toEqual(new Date(1_000));
    expect(meta.expiresInMs).toBe(8_000);
    expect(meta.expired).toBe(false);
  });

  it("handles payloads without temporal claims and expired tokens", () => {
    expect(getTokenMeta(tokenFor({ sub: "operator" }))).toEqual({
      payload: { sub: "operator" },
      expDate: null,
      iatDate: null,
      expiresInMs: null,
      expired: null,
    });

    vi.spyOn(Date, "now").mockReturnValue(20_000);
    expect(getTokenMeta(tokenFor({ exp: 10 })).expired).toBe(true);
    expect(getTokenMeta(tokenFor({ iat: 5 })).expired).toBeNull();
  });
});
