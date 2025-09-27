[![Test](https://img.shields.io/github/actions/workflow/status/FlowMCP/mcp-auth-middleware/test-on-release.yml)](https://github.com/FlowMCP/mcp-auth-middleware/actions) ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

# MCP Auth Middleware

**OAuth 2.1 compliant authentication middleware for Model Context Protocol (MCP) 2.1 servers.** Provides secure, production-ready authentication strategies for MCP server implementations with Express.js integration.

Fully compliant with [MCP 2.1 Authorization Specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization).

## Quickstart

```bash
git clone https://github.com/FlowMCP/mcp-auth-middleware.git
cd mcp-auth-middleware
npm install
```

```javascript
import { McpAuthMiddleware } from './src/index.mjs'

const mcpAuth = await McpAuthMiddleware.create({
    authType: 'scalekit',
    options: {
        providerUrl: 'https://your-org.scalekit.com',
        clientId: 'your_client_id',
        clientSecret: 'your_client_secret',
        resource: 'http://localhost:3002/',
        protectedResourceMetadata: {},
        toolScopes: {}
    },
    attachedRoutes: ['/']
})

app.use(mcpAuth.router())
```

## Features

- **MCP Server Authentication**: Four authentication strategies specifically designed for Model Context Protocol servers
- **ScaleKit OAuth 2.1**: Production-ready OAuth 2.1 authentication for secure MCP deployments
- **AuthKit OAuth 2.1**: WorkOS AuthKit integration for enterprise-grade OAuth 2.1 authentication
- **Development Support**: Free-route and static-bearer authentication for MCP testing and development
- **Express.js Integration**: Ready-to-use router() method for seamless Express.js integration
- **Route Protection**: Configurable route-based protection for MCP tools and endpoints
- **Logging**: Configurable authentication logging for debugging and monitoring

## Table of Contents

- [Methods](#methods)
  - [McpAuthMiddleware.create()](#mcpauthmiddlewarecreate)
- [Authentication Types](#authentication-types)
  - [Free Route](#free-route)
  - [Static Bearer](#static-bearer)
  - [ScaleKit OAuth 2.1](#scalekit-oauth-21)
  - [AuthKit OAuth 2.1](#authkit-oauth-21)
- [Contribution](#contribution)
- [License](#license)

## Methods

### McpAuthMiddleware.create()

Creates an authentication middleware instance for MCP servers based on the specified authentication type.

**Method**
```javascript
.create( { authType, options, attachedRoutes, silent } )
```

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| authType | string | Authentication type: `'free-route'`, `'static-bearer'`, `'scalekit'`, `'authkit'` | Yes |
| options | object | Authentication-specific configuration object | Yes |
| attachedRoutes | array of strings | Routes to protect. Example: `['/']` | No |
| silent | boolean | Disable console logging. Defaults to `false` | No |

**Example**
```javascript
const mcpAuth = await McpAuthMiddleware.create({
    authType: 'scalekit',
    options: {
        providerUrl: 'https://company.scalekit.com',
        clientId: 'sk_client_abc123',
        clientSecret: 'sk_secret_xyz789',
        resource: 'http://localhost:3002/',
        protectedResourceMetadata: { "mcp_server": true },
        toolScopes: { "greeting_tool": ["read"] }
    },
    attachedRoutes: ['/'],
    silent: false
})
```

**Returns**
```javascript
{
    router: Function  // Express.js router middleware function
}
```

## Authentication Types

### Free Route

No authentication required - suitable for development and testing MCP servers.

```javascript
const freeAuth = await McpAuthMiddleware.create({
    authType: 'free-route',
    options: {},
    attachedRoutes: [],
    silent: false
})
```

### Static Bearer

Simple Bearer token authentication for internal MCP servers.

```javascript
const bearerAuth = await McpAuthMiddleware.create({
    authType: 'static-bearer',
    options: {
        bearerToken: 'your-secret-bearer-token'
    },
    attachedRoutes: ['/'],
    silent: false
})
```

**Required Request Header:**
```json
{
    "Authorization": "Bearer your-secret-bearer-token"
}
```

### ScaleKit OAuth 2.1

Production-ready OAuth 2.1 authentication via ScaleKit platform for MCP 2.1 compliant servers.

```javascript
const scalekitAuth = await McpAuthMiddleware.create({
    authType: 'scalekit',
    options: {
        providerUrl: 'https://your-org.scalekit.com',
        clientId: 'sk_client_abc123',
        clientSecret: 'sk_secret_xyz789',
        resource: 'http://localhost:3002/',
        protectedResourceMetadata: {
            "mcp_server_id": "res_123",
            "tools": ["greeting", "weather"]
        },
        toolScopes: {
            "greeting_tool": ["read", "write"],
            "weather_tool": ["read"]
        }
    },
    attachedRoutes: ['/'],
    silent: false
})
```

**Options for ScaleKit:**

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| providerUrl | string | ScaleKit organization URL | Yes |
| clientId | string | ScaleKit client ID | Yes |
| clientSecret | string | ScaleKit client secret | Yes |
| resource | string | MCP server URL/identifier | Yes |
| protectedResourceMetadata | object | Metadata for the protected MCP resource | Yes |
| toolScopes | object | Tool-specific permission scopes | Yes |

### AuthKit OAuth 2.1

Enterprise-grade OAuth 2.1 authentication via WorkOS AuthKit for MCP 2.1 compliant servers.

```javascript
const authkitAuth = await McpAuthMiddleware.create({
    authType: 'authkit',
    options: {
        authKitDomain: 'your-authkit-domain.workos.com',
        clientId: 'client_01K5SH7EEBYX79PEQXTN19WNAB',
        clientSecret: 'sk_test_abc123xyz789',
        expectedAudience: 'client_01K5SH7EEBYX79PEQXTN19WNAB',
        protectedResourceMetadata: JSON.stringify({
            "resource": "http://localhost:3000/",
            "authorization_servers": ["https://your-authkit-domain.workos.com"],
            "bearer_methods_supported": ["header"]
        }),
        toolScopes: {
            "ping_tool": ["read"],
            "data_tool": ["read", "write"]
        }
    },
    attachedRoutes: ['/'],
    silent: false
})
```

**Options for AuthKit:**

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| authKitDomain | string | WorkOS AuthKit domain | Yes |
| clientId | string | AuthKit client ID | Yes |
| clientSecret | string | AuthKit client secret | Yes |
| expectedAudience | string | Expected JWT audience (usually client ID) | Yes |
| protectedResourceMetadata | string | JSON string of protected resource metadata | Yes |
| toolScopes | object | Tool-specific permission scopes | Yes |

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.