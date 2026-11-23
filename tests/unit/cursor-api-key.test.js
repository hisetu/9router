import { describe, it, expect, vi } from "vitest";
import {
  isCursorUserApiKey,
  decodeJwtExpiry,
  exchangeCursorApiKey,
  refreshCursorCredentials,
} from "../../open-sse/services/cursorApiKey.js";

const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const jwt = (claims) => `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(claims)}.sig`;
const API_KEY = "crsr_" + "a1B2c3D4".repeat(12); // fake, 101 chars

function mockFetch(status, body) {
  return vi.fn(async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status }));
}

describe("isCursorUserApiKey", () => {
  it("accepts short opaque keys", () => {
    expect(isCursorUserApiKey(API_KEY)).toBe(true);
    expect(isCursorUserApiKey(`  ${API_KEY}\n`)).toBe(true);
  });
  it("rejects IDE session tokens (JWT or encrypted blob) and junk", () => {
    expect(isCursorUserApiKey(jwt({ exp: 1 }))).toBe(false);
    expect(isCursorUserApiKey("A".repeat(711))).toBe(false);
    expect(isCursorUserApiKey("abc+def/ghi=".repeat(5))).toBe(false);
    expect(isCursorUserApiKey("short")).toBe(false);
    expect(isCursorUserApiKey(undefined)).toBe(false);
  });
});

describe("exchangeCursorApiKey", () => {
  it("posts the key as Bearer to exchange_user_api_key and returns tokens with JWT expiry", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const at = jwt({ exp, sub: "user_1" });
    const rt = jwt({ exp: exp + 10 });
    const f = mockFetch(200, { accessToken: at, refreshToken: rt });
    const out = await exchangeCursorApiKey(API_KEY, { fetchImpl: f });
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("https://api2.cursor.sh/auth/exchange_user_api_key");
    expect(init.method).toBe("POST");
    expect(init.headers.Authorization).toBe(`Bearer ${API_KEY}`);
    expect(init.body).toBe("{}");
    expect(out).toEqual({ accessToken: at, refreshToken: rt, expiresAt: new Date(exp * 1000).toISOString() });
  });
  it("throws with status on rejection, without echoing the key", async () => {
    const f = mockFetch(401, { code: "unauthenticated" });
    await expect(exchangeCursorApiKey(API_KEY, { fetchImpl: f })).rejects.toMatchObject({ status: 401 });
    await exchangeCursorApiKey(API_KEY, { fetchImpl: f }).catch((e) => expect(e.message).not.toContain(API_KEY));
  });
  it("falls back to ~50 min expiry when the token has no exp", async () => {
    const f = mockFetch(200, { accessToken: "opaque-token", refreshToken: "r" });
    const out = await exchangeCursorApiKey(API_KEY, { fetchImpl: f });
    const ms = Date.parse(out.expiresAt) - Date.now();
    expect(ms).toBeGreaterThan(45 * 60 * 1000);
    expect(ms).toBeLessThanOrEqual(50 * 60 * 1000);
  });
  it("refuses non-key input without calling the network", async () => {
    const f = mockFetch(200, {});
    await expect(exchangeCursorApiKey(jwt({}), { fetchImpl: f })).rejects.toThrow();
    expect(f).not.toHaveBeenCalled();
  });
});

describe("refreshCursorCredentials", () => {
  it("returns null for IDE-imported connections (no apiKey) — previous behaviour", async () => {
    const f = mockFetch(200, {});
    expect(await refreshCursorCredentials({ accessToken: "x", refreshToken: null }, null, { fetchImpl: f })).toBeNull();
    expect(f).not.toHaveBeenCalled();
  });
  it("re-mints tokens from the stored apiKey", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const f = mockFetch(200, { accessToken: jwt({ exp }), refreshToken: jwt({ exp }) });
    const out = await refreshCursorCredentials({ apiKey: API_KEY, accessToken: "old" }, null, { fetchImpl: f });
    expect(out.accessToken).not.toBe("old");
    expect(out.expiresAt).toBe(new Date(exp * 1000).toISOString());
  });
  it("returns null (not throw) when the exchange fails", async () => {
    const f = mockFetch(403, "forbidden");
    expect(await refreshCursorCredentials({ apiKey: API_KEY }, null, { fetchImpl: f })).toBeNull();
  });
});

describe("decodeJwtExpiry", () => {
  it("handles non-JWT input", () => {
    expect(decodeJwtExpiry("nope")).toBeNull();
    expect(decodeJwtExpiry(jwt({}))).toBeNull();
  });
});
