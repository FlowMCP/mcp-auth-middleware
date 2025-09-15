const oauth21ScalekitSchema = {
    name: 'OAuth 2.1 with ScaleKit',
    description: 'OAuth 2.1 implementation for ScaleKit MCP servers',
    authType: 'oauth21_scalekit',

    requiredFields: [
        {
            key: 'providerUrl',
            type: 'string',
            description: 'OAuth provider URL (ScaleKit hosted or custom domain)',
            example: 'https://flowmcp-afaeuirdaafqi.scalekit.dev'
        },
        {
            key: 'mcpId',
            type: 'string',
            description: 'ScaleKit MCP Server Identifier (res_...)',
            example: 'res_90153735103187214'
        },
        {
            key: 'clientId',
            type: 'string',
            description: 'ScaleKit application client ID',
            example: 'skc_abc123def456ghi789'
        },
        {
            key: 'clientSecret',
            type: 'string',
            description: 'ScaleKit application client secret',
            example: 'secret_abc123def456'
        },
        {
            key: 'resource',
            type: 'string',
            description: 'Resource identifier URL (must match MCP server base URL)',
            example: 'https://community.flowmcp.org/mcp/sse'
        },
        {
            key: 'scope',
            type: 'string',
            description: 'OAuth scopes to request (space-separated)',
            example: 'mcp:tools:* mcp:resources:read mcp:resources:write'
        }
    ],

    optionalFields: [
        {
            key: 'resourceDocumentation',
            type: 'string',
            description: 'Documentation URL for the MCP resource',
            example: 'https://community.flowmcp.org/mcp/sse/docs'
        },
        {
            key: 'routePath',
            type: 'string',
            description: 'Route path where MCP server is mounted',
            example: '/mcp/sse'
        },
        {
            key: 'redirectUri',
            type: 'string',
            description: 'OAuth redirect URI (auto-generated if not provided)',
            example: 'https://localhost:3000/api/auth/callback'
        },
        {
            key: 'responseType',
            type: 'string',
            description: 'OAuth response type',
            default: 'code',
            allowedValues: [ 'code' ]
        },
        {
            key: 'grantType',
            type: 'string',
            description: 'OAuth grant type',
            default: 'authorization_code',
            allowedValues: [ 'authorization_code', 'client_credentials' ]
        },
        {
            key: 'tokenEndpoint',
            type: 'string',
            description: 'Custom token endpoint (auto-discovered if not provided)',
            example: 'https://subdomain.scalekit.dev/oauth/token'
        },
        {
            key: 'userInfoEndpoint',
            type: 'string',
            description: 'Custom userinfo endpoint (auto-discovered if not provided)',
            example: 'https://subdomain.scalekit.dev/userinfo'
        }
    ],

    defaults: {
        responseType: 'code',
        grantType: 'authorization_code',
        scope: 'mcp:tools:* mcp:resources:read mcp:resources:write'
    },

    validation: {
        providerUrl: {
            pattern: /^https:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            message: 'providerUrl must be a valid HTTPS URL'
        },
        mcpId: {
            pattern: /^res_[0-9]+$/,
            message: 'mcpId must be a valid ScaleKit resource identifier (res_...)'
        },
        clientId: {
            minLength: 10,
            message: 'clientId must be at least 10 characters long'
        },
        clientSecret: {
            minLength: 10,
            message: 'clientSecret must be at least 10 characters long'
        },
        resource: {
            pattern: /^https?:\/\/.+$/,
            message: 'resource must be a valid URL'
        },
        scope: {
            pattern: /^[a-zA-Z0-9_\s:.*-]+$/,
            message: 'scope must contain only valid OAuth scope characters'
        }
    }
}

export { oauth21ScalekitSchema }