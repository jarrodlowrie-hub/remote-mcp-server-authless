import { OAuthProvider, insufficientScope } from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";

interface ConnectorEnv {
	OAUTH_KV: KVNamespace;
}

const ORIGIN =
	"https://remote-mcp-server-authless.jarrod-lowrie.workers.dev";

function createServer() {
	const server = new McpServer({
		name: "Basecamp 2 Read-Only Connector",
		version: "0.1.0",
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
					text: "Authentication foundation installed. Basecamp access is not configured yet.",
				},
			],
		}),
	);

	return server;
}

const mcpHandler = createMcpHandler(createServer);

export default new OAuthProvider<ConnectorEnv>({
	apiRoute: "/mcp",

	apiHandler: {
		fetch(request, env, ctx) {
			if (!ctx.auth.scope.includes("mcp:read")) {
				return insufficientScope(ctx.auth, ["mcp:read"]);
			}

			return mcpHandler(request, env, ctx);
		},
	},

	defaultHandler: {
		async fetch(request) {
			const path = new URL(request.url).pathname;

			if (path === "/authorize" || path === "/basecamp/callback") {
				return new Response(
					"Basecamp sign-in is not configured yet. Access remains disabled.",
					{
						status: 503,
						headers: {
							"Content-Type": "text/plain; charset=utf-8",
							"Cache-Control": "no-store",
						},
					},
				);
			}

			return new Response("Not found", { status: 404 });
		},
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
