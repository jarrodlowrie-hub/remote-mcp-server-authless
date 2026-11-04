import {
  OAuthError,
  OAuthProvider,
  authorizationErrorRedirect,
  insufficientScope,
} from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";

interface ConnectorEnv {
  OAUTH_KV: KVNamespace;
  BASECAMP_CLIENT_ID: string;
  BASECAMP_CLIENT_SECRET: string;
}

interface BasecampTokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  error?: string;
}

interface BasecampAuthorization {
  accounts?: Array<{
    id: number | string;
    product: string;
    name?: string;
    href?: string;
  }>;
}

const ORIGIN =
  "https://remote-mcp-server-authless.jarrod-lowrie.workers.dev";
const BASECAMP_ACCOUNT_ID = "2872754";
const BASECAMP_PRODUCT = "bcx";
const BASECAMP_REDIRECT_URI = `${ORIGIN}/basecamp/callback`;
const BASECAMP_AUTHORIZE_URL =
  "https://launchpad.37signals.com/authorization/new";
const BASECAMP_TOKEN_URL =
  "https://launchpad.37signals.com/authorization/token";
const BASECAMP_AUTHORIZATION_URL =
  "https://launchpad.37signals.com/authorization.json";
const USER_AGENT = "Conversion Geeks LLC Basecamp 2 MCP Connector";

function createServer() {
  const server = new McpServer({
    name: "Basecamp 2 Read-Only Connector",
    version: "0.2.0",
  });

  server.registerTool(
    "connector_status",
    {
      description: "Check the connector setup status.",
      inputSchema: z.object({}),
    },
    async () => ({
      content: [
        {
          type: "text",
          text: "The Claude-facing OAuth foundation and Basecamp 2 authorization flow are installed. Read-only Basecamp tools are the next implementation step.",
        },
      ],
    }),
  );

  return server;
}

const mcpHandler = createMcpHandler(createServer);

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[character];
  });
}

function pageResponse(message: string, status = 400): Response {
  return new Response(
    `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Basecamp connector</title><body><main><h1>Basecamp 2 connector</h1><p>${escapeHtml(message)}</p></main></body></html>`,
    {
      status,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        "X-Frame-Options": "DENY",
      },
    },
  );
}

function consentPage(
  clientName: string,
  redirectHost: string,
  scopes: string[],
  handle: string,
): string {
  const safeName = escapeHtml(clientName);
  const safeHost = escapeHtml(redirectHost);
  const scopeOptions = scopes
    .map(
      (scope) =>
        `<label><input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked> ${escapeHtml(scope)}</label>`,
    )
    .join("<br>");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize Basecamp 2 connector</title>
</head>
<body>
<main>
<h1>Allow ${safeName} to use the Basecamp 2 connector?</h1>
<p>The requesting application will receive access to this connector at <strong>${safeHost}</strong>.</p>
<p>The connector is being configured for read-only access to Basecamp 2 account ${BASECAMP_ACCOUNT_ID}.</p>
<p>After you continue, 37signals will ask you to sign in and approve the connector's Basecamp access. Your Basecamp password is never shared with this connector.</p>
<form method="post" action="/authorize">
<input type="hidden" name="handle" value="${escapeHtml(handle)}">
<fieldset><legend>Connector permission</legend>${scopeOptions}</fieldset>
<p><button type="submit" name="decision" value="approve">Continue to Basecamp sign-in</button>
<button type="submit" name="decision" value="deny">Deny</button></p>
</form>
</main>
</body>
</html>`;
}

async function exchangeBasecampCode(
  env: ConnectorEnv,
  code: string,
): Promise<BasecampTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: env.BASECAMP_CLIENT_ID,
    client_secret: env.BASECAMP_CLIENT_SECRET,
    redirect_uri: BASECAMP_REDIRECT_URI,
    code,
  });

  const response = await fetch(BASECAMP_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      "User-Agent": USER_AGENT,
    },
    body,
  });

  const token = (await response.json()) as BasecampTokenResponse;
  if (!response.ok || !token.access_token || !token.refresh_token) {
    throw new Error("Basecamp did not issue the expected OAuth tokens.");
  }
  return token;
}

async function verifyBasecampAccount(
  accessToken: string,
): Promise<boolean> {
  const response = await fetch(BASECAMP_AUTHORIZATION_URL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
      "User-Agent": USER_AGENT,
    },
  });

  if (!response.ok) {
    throw new Error("Basecamp account authorization could not be verified.");
  }

  const authorization =
    (await response.json()) as BasecampAuthorization;

  return (
    authorization.accounts?.some(
      (account) =>
        String(account.id) === BASECAMP_ACCOUNT_ID &&
        account.product === BASECAMP_PRODUCT,
    ) ?? false
  );
}

async function refreshBasecampToken(
  env: ConnectorEnv,
  refreshToken: string,
): Promise<BasecampTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: env.BASECAMP_CLIENT_ID,
    client_secret: env.BASECAMP_CLIENT_SECRET,
  });

  const response = await fetch(BASECAMP_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      "User-Agent": USER_AGENT,
    },
    body,
  });

  const token = (await response.json()) as BasecampTokenResponse;
  if (!response.ok || !token.access_token) {
    if (response.status === 400 && token.error === "invalid_grant") {
      throw new OAuthError("invalid_grant", {
        description: "Basecamp authorization has expired or been revoked. Please connect Basecamp again.",
      });
    }
    throw new OAuthError("temporarily_unavailable", {
      description: "Basecamp token renewal is temporarily unavailable. Please try again.",
      statusCode: 503,
    });
  }
  return token;
}

const mcpHandlerWithOAuth = createMcpHandler(createServer);

export default new OAuthProvider<ConnectorEnv>({
  apiRoute: "/mcp",

  apiHandler: {
    fetch(request, env, ctx) {
      if (!ctx.auth.scope.includes("mcp:read")) {
        return insufficientScope(ctx.auth, ["mcp:read"]);
      }

      return mcpHandlerWithOAuth(request, env, ctx);
    },
  },

  defaultHandler: {
    async fetch(request, env) {
      const url = new URL(request.url);
      const oauth = env.OAUTH_PROVIDER;

      if (url.pathname === "/authorize" && request.method === "GET") {
        try {
          const authRequest = await oauth.parseAuthRequest(request);
          const details = await oauth.describeConsent(authRequest);
          const consent = await oauth.beginConsent(authRequest);
          consent.headers.set("Content-Type", "text/html; charset=utf-8");
          consent.headers.set("Cache-Control", "no-store");
          return new Response(
            consentPage(
              details.clientName,
              details.redirectHost,
              details.scope,
              consent.handle,
            ),
            { headers: consent.headers },
          );
        } catch {
          return pageResponse(
            "The authorization request could not be validated. Please restart the connection from your MCP client.",
            400,
          );
        }
      }

      if (url.pathname === "/authorize" && request.method === "POST") {
        try {
          const form = await request.formData();
          const handle = String(form.get("handle") ?? "");
          if (!handle) {
            return pageResponse("The authorization session is missing. Please restart the connection.");
          }

          if (form.get("decision") !== "approve") {
            const denied = await oauth.denyConsent(request, handle);
            return new Response(null, {
              status: 302,
              headers: denied.headers,
            });
          }

          const approved = await oauth.approveConsent(request, handle, {
            scope: form.getAll("scope").map(String),
          });
          const { state, headers } = await oauth.beginUpstream(
            approved.request,
            { headers: approved.headers },
          );

          const basecampUrl = new URL(BASECAMP_AUTHORIZE_URL);
          basecampUrl.searchParams.set("response_type", "code");
          basecampUrl.searchParams.set(
            "client_id",
            env.BASECAMP_CLIENT_ID,
          );
          basecampUrl.searchParams.set(
            "redirect_uri",
            BASECAMP_REDIRECT_URI,
          );
          basecampUrl.searchParams.set("state", state);

          headers.set("Location", basecampUrl.toString());
          return new Response(null, { status: 302, headers });
        } catch {
          return pageResponse(
            "The authorization could not be started. Please restart the connection.",
            400,
          );
        }
      }

      if (
        url.pathname === "/basecamp/callback" &&
        request.method === "GET"
      ) {
        let originalRequest: Awaited<
          ReturnType<typeof oauth.finishUpstream>
        >["request"];
        let callbackHeaders: Headers;

        try {
          const resumed = await oauth.finishUpstream(request);
          originalRequest = resumed.request;
          callbackHeaders = resumed.headers;
        } catch {
          return pageResponse(
            "The Basecamp callback could not be validated. Please restart the connection.",
            400,
          );
        }

        if (url.searchParams.has("error")) {
          callbackHeaders.set(
            "Location",
            authorizationErrorRedirect(originalRequest, "access_denied"),
          );
          return new Response(null, {
            status: 302,
            headers: callbackHeaders,
          });
        }

        const code = url.searchParams.get("code");
        if (!code) {
          return pageResponse(
            "Basecamp did not return an authorization code. Please restart the connection.",
            400,
          );
        }

        try {
          const token = await exchangeBasecampCode(env, code);
          const accountIsAuthorized = await verifyBasecampAccount(
            token.access_token,
          );

          if (!accountIsAuthorized) {
            return pageResponse(
              "The signed-in Basecamp user has not authorized Basecamp 2 account 2872754 for this connector. No Claude access token was issued.",
              403,
            );
          }

          const { redirectTo } = await oauth.completeAuthorization({
            request: originalRequest,
            userId: `basecamp2-${crypto.randomUUID()}`,
            metadata: {},
            scope: originalRequest.scope,
            props: {
              basecampAccessToken: token.access_token,
              basecampRefreshToken: token.refresh_token,
              basecampAccountId: BASECAMP_ACCOUNT_ID,
              basecampApiRoot: `https://basecamp.com/${BASECAMP_ACCOUNT_ID}/api/v1`,
            },
          });

          callbackHeaders.set("Location", redirectTo);
          return new Response(null, {
            status: 302,
            headers: callbackHeaders,
          });
        } catch {
          callbackHeaders.set(
            "Location",
            authorizationErrorRedirect(
              originalRequest,
              "temporarily_unavailable",
            ),
          );
          return new Response(null, {
            status: 302,
            headers: callbackHeaders,
          });
        }
      }

      return new Response("Not found", { status: 404 });
    },
  },

  tokenExchangeCallback: async ({ grantType, props, env }) => {
    if (grantType !== "refresh_token") return;

    if (
      !props?.basecampRefreshToken ||
      props.basecampAccountId !== BASECAMP_ACCOUNT_ID
    ) {
      throw new OAuthError("invalid_grant", {
        description: "The Basecamp authorization is missing. Please connect Basecamp again.",
      });
    }

    const token = await refreshBasecampToken(
      env,
      props.basecampRefreshToken,
    );

    return {
      newProps: {
        ...props,
        basecampAccessToken: token.access_token,
        basecampRefreshToken:
          token.refresh_token || props.basecampRefreshToken,
      },
    };
  },

  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  scopesSupported: ["mcp:read"],
  requiredScopes: ["mcp:read"],
  clientIdMetadataDocumentEnabled: true,

  resourceMetadata: {
    resource: `${ORIGIN}/mcp`,
    authorization_servers: [ORIGIN],
  },
});
