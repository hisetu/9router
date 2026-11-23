import { describe, it, expect } from "vitest";
import { parseAgentEndStream } from "../../open-sse/executors/cursor.js";

const len = (n) => { const out = []; while (n > 0x7f) { out.push((n & 0x7f) | 0x80); n >>>= 7; } out.push(n); return out; };
const str = (field, s) => { const b = Buffer.from(s, "utf8"); return Buffer.from([(field << 3) | 2, ...len(b.length), ...b]); };
const msg = (field, inner) => Buffer.from([(field << 3) | 2, ...len(inner.length), ...inner]);
const varint = (field, v) => Buffer.from([(field << 3) | 0, ...len(v)]);

function errorDetails(errorEnum, title, detail) {
  const custom = Buffer.concat([str(1, title), str(2, detail)]);
  return Buffer.concat([varint(1, errorEnum), msg(2, custom)]).toString("base64").replace(/=+$/, "");
}
const endStream = (obj) => Buffer.from(JSON.stringify(obj), "utf8");

describe("parseAgentEndStream", () => {
  it("surfaces Cursor's usage-limit title and detail with HTTP 429", () => {
    const out = parseAgentEndStream(endStream({
      error: {
        code: "resource_exhausted",
        message: "Error",
        details: [{ type: "aiserver.v1.ErrorDetails", value: errorDetails(7, "You've hit your usage limit", "Your usage limits will reset when your monthly cycle ends on 12/8/2026.") }],
      },
    }));
    expect(out.status).toBe(429);
    expect(out.code).toBe("resource_exhausted");
    expect(out.message).toBe("Cursor AgentService resource_exhausted: You've hit your usage limit: Your usage limits will reset when your monthly cycle ends on 12/8/2026.");
  });

  it("falls back to the Connect message when details cannot be decoded", () => {
    const out = parseAgentEndStream(endStream({ error: { code: "unauthenticated", message: "token expired", details: [{ type: "x.Other", value: "AAAA" }] } }));
    expect(out).toMatchObject({ status: 401, message: "Cursor AgentService unauthenticated: token expired" });
  });

  it("maps unknown codes to 400", () => {
    expect(parseAgentEndStream(endStream({ error: { code: "internal", message: "boom" } })).status).toBe(400);
  });

  it("ignores a normal end-of-stream (no error) and non-JSON payloads", () => {
    expect(parseAgentEndStream(endStream({}))).toBeNull();
    expect(parseAgentEndStream(endStream({ metadata: { a: ["b"] } }))).toBeNull();
    expect(parseAgentEndStream(Buffer.from([0x0a, 0x01]))).toBeNull();
  });
});
