// Cursor user API keys (dashboard → API Keys, "Cursor CLI and SDK" scope).
//
// The IDE endpoints used by the Cursor executor only accept a session access
// token, so a user API key has to be exchanged first. This mirrors what the
// official Cursor CLI does for `agent --api-key` / CURSOR_API_KEY:
//   POST {api2}/auth/exchange_user_api_key, Authorization: Bearer <apiKey>, body {}
//   → { accessToken, refreshToken }
// The minted access token is short-lived (about one hour), so the connection
// keeps the API key and re-exchanges it whenever the token is about to expire.

export const CURSOR_API_BASE_URL = "https://api2.cursor.sh";
const EXCHANGE_PATH = "/auth/exchange_user_api_key";

// User API keys are short opaque strings. IDE session tokens are either JWTs
// (three dot-separated parts) or, since Cursor encrypts them at rest, long
// opaque blobs of several hundred characters — neither matches this shape.
export function isCursorUserApiKey(value) {
  if (typeof value !== "string") return false;
  const v = value.trim();
  return v.length >= 32 && v.length <= 200 && /^[A-Za-z0-9_-]+$/.test(v);
}

export function decodeJwtExpiry(token) {
  try {
    const parts = String(token).split(".");
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    return typeof payload.exp === "number" ? new Date(payload.exp * 1000).toISOString() : null;
  } catch {
    return null;
  }
}

export async function exchangeCursorApiKey(apiKey, { fetchImpl = fetch, baseUrl = CURSOR_API_BASE_URL, log } = {}) {
  if (!isCursorUserApiKey(apiKey)) throw new Error("Not a Cursor user API key");
  const res = await fetchImpl(`${baseUrl}${EXCHANGE_PATH}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey.trim()}` },
    body: "{}",
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) {
    let detail = "";
    try { detail = (await res.text()).slice(0, 200); } catch {}
    log?.error?.("TOKEN_REFRESH", "Cursor API key exchange failed", { status: res.status });
    const err = new Error(`Cursor API key exchange failed: HTTP ${res.status}${detail ? ` ${detail}` : ""}`);
    err.status = res.status;
    throw err;
  }
  const data = await res.json();
  if (typeof data?.accessToken !== "string" || !data.accessToken) {
    throw new Error("Cursor API key exchange returned no accessToken");
  }
  return {
    accessToken: data.accessToken,
    refreshToken: typeof data.refreshToken === "string" && data.refreshToken ? data.refreshToken : data.accessToken,
    // Fall back to a conservative 50 minutes if the token carries no exp claim.
    expiresAt: decodeJwtExpiry(data.accessToken) || new Date(Date.now() + 50 * 60 * 1000).toISOString(),
  };
}

// Refresh handler: re-exchange the stored API key. Connections imported from
// an IDE session token have no apiKey and keep the previous behaviour (null).
export async function refreshCursorCredentials(credentials, log, options = {}) {
  const apiKey = credentials?.apiKey;
  if (!isCursorUserApiKey(apiKey)) return null;
  try {
    const tokens = await exchangeCursorApiKey(apiKey, { ...options, log });
    log?.info?.("TOKEN_REFRESH", "Cursor access token re-minted from API key", { expiresAt: tokens.expiresAt });
    return tokens;
  } catch (error) {
    log?.error?.("TOKEN_REFRESH", "Cursor API key refresh failed", { error: error.message });
    return null;
  }
}
