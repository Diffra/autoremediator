import type http from "node:http";

import { describe, expect, it } from "vitest";

import { authorizeRole, createSignedJwt, getRoleForToken } from "./http-auth.js";

describe("static token lookup", () => {
  const configured = "admin:s3cret-token,reader:read-only-token";

  it("returns the role of the matching token", () => {
    expect(getRoleForToken("s3cret-token", configured, undefined)).toBe("admin");
    expect(getRoleForToken("read-only-token", configured, undefined)).toBe("reader");
  });

  it("refuses a token that is a prefix or an extension of a configured one", () => {
    expect(getRoleForToken("s3cret", configured, undefined)).toBeUndefined();
    expect(getRoleForToken("s3cret-token-and-more", configured, undefined)).toBeUndefined();
  });

  it("refuses a token that differs only by trailing zero bytes", () => {
    expect(getRoleForToken("s3cret-token\0", configured, undefined)).toBeUndefined();
  });

  it("handles tokens longer than the comparison block", () => {
    const long = "x".repeat(2000);
    expect(getRoleForToken(long, `operator:${long}`, undefined)).toBe("operator");
    expect(getRoleForToken(`${long}y`, `operator:${long}`, undefined)).toBeUndefined();
  });

  it("never matches an empty secret", () => {
    expect(getRoleForToken("", "admin:", undefined)).toBeUndefined();
  });

  it("is development mode, with every request an admin, when nothing is configured", () => {
    expect(getRoleForToken("anything", undefined, undefined)).toBe("admin");
  });
});

describe("authorizeRole with an explicit environment", () => {
  const request = (token: string): http.IncomingMessage =>
    ({ headers: { authorization: `Bearer ${token}` } }) as http.IncomingMessage;

  it("checks the token against the tokens of that environment, not the process's", () => {
    const env = { AUTOREMEDIATOR_API_TOKENS: "reader:good-token" };

    expect(authorizeRole(request("bad-token"), "reader", "GET /x", env)).toMatchObject({
      ok: false,
      status: 401,
    });
    expect(authorizeRole(request("good-token"), "reader", "GET /x", env)).toEqual({ ok: true });
    expect(authorizeRole(request("good-token"), "admin", "POST /x", env)).toMatchObject({
      ok: false,
      status: 403,
    });
  });

  it("verifies a JWT against the secret of that environment", () => {
    const env = { AUTOREMEDIATOR_JWT_SECRET: "env-secret" };
    const good = createSignedJwt({ role: "admin" }, "env-secret");
    const forged = createSignedJwt({ role: "admin" }, "other-secret");

    expect(authorizeRole(request(good), "admin", "POST /x", env)).toEqual({ ok: true });
    expect(authorizeRole(request(forged), "admin", "POST /x", env)).toMatchObject({
      ok: false,
      status: 401,
    });
  });
});
