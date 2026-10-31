import { createRemoteJWKSet, errors, jwtVerify } from "jose";

import { McpApiHandler } from "./mcp.js";
import type { WorkerEnv } from "./env.js";

/** True when either Access setting is present, so a half-configured Worker never falls back to GitHub OAuth. */
export function usesAccess(env: WorkerEnv): boolean {
  return Boolean(env.CF_ACCESS_TEAM_DOMAIN || env.CF_ACCESS_AUD);
}

let keys:
  { issuer: string; set: ReturnType<typeof createRemoteJWKSet> } | undefined;

function keySet(issuer: string) {
  if (keys?.issuer !== issuer) {
    keys = {
      issuer,
      set: createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`)),
    };
  }
  return keys.set;
}

/** Errors a bad, expired or forged token produces, as opposed to an outage or misconfiguration. */
const REJECTED_TOKEN_ERRORS = [
  errors.JWTClaimValidationFailed,
  errors.JWSSignatureVerificationFailed,
  errors.JWSInvalid,
  errors.JWTInvalid,
  errors.JOSEAlgNotAllowed,
  errors.JWKSNoMatchingKey,
];

async function isAuthorized(
  request: Request,
  teamDomain: string,
  audience: string,
): Promise<boolean> {
  const assertion = request.headers.get("cf-access-jwt-assertion");
  if (!assertion) return false;

  const issuer = `https://${teamDomain}`;
  try {
    await jwtVerify(assertion, keySet(issuer), {
      issuer,
      audience,
      algorithms: ["RS256"],
    });
    return true;
  } catch (error) {
    if (!REJECTED_TOKEN_ERRORS.some((type) => error instanceof type)) {
      console.error("access: could not verify token:", error);
    }
    return false;
  }
}

/** Serves /mcp to requests carrying a valid Access token: 404 elsewhere, 401 without one. */
export const AccessHandler = {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    const { CF_ACCESS_TEAM_DOMAIN: teamDomain, CF_ACCESS_AUD: audience } = env;
    if (!teamDomain || !audience) {
      return new Response(
        "Cloudflare Access needs both CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD",
        { status: 500 },
      );
    }
    if (new URL(request.url).pathname !== "/mcp") {
      return new Response("Not found", { status: 404 });
    }
    if (!(await isAuthorized(request, teamDomain, audience))) {
      return new Response("Unauthorized", { status: 401 });
    }
    return McpApiHandler.fetch(request, env);
  },
};
