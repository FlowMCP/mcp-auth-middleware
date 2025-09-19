# MCP OAuth Middleware

[![Test](https://img.shields.io/github/actions/workflow/status/flowmcp/oauth-middleware/test-on-release.yml)]() ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Express-compatible authentication middleware for securing MCP server endpoints with OAuth 2.1 (ScaleKit) and Bearer token support. **Version 1.0** with simplified API and MCP Spec compliance.

## 🚨 Breaking Changes in v1.0

**Version 1.0 introduces breaking changes.** The API has been simplified and modernized:

- **❌ Auth0 support deprecated** → ✅ ScaleKit OAuth21 only
- **❌ Complex route objects** → ✅ Simple `attachedRoutes` arrays
- **❌ `routes` top-level key** → ✅ `staticBearer` + `oauth21` keys
- **❌ Route-level discovery** → ✅ Root-level discovery (MCP compliant)

See [Migration Guide](#migration-guide) for upgrade instructions.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication Types](#authentication-types)
  - [StaticBearer](#staticbearer)
  - [OAuth21 ScaleKit](#oauth21-scalekit)
  - [Mixed Authentication](#mixed-authentication)
- [API Reference](#api-reference)
- [Migration Guide](#migration-guide)
- [Testing](#testing)
- [License](#license)

## Installation

```bash
npm install mcp-auth-middleware
```

## Quick Start

### StaticBearer Authentication

```javascript
import { McpAuthMiddleware } from 'mcp-auth-middleware'
import express from 'express'

const middleware = await McpAuthMiddleware.create({
    staticBearer: {
        tokenSecret: 'your-secure-bearer-token-here',
        attachedRoutes: ['/api', '/tools']
    },
    baseUrl: 'https://api.example.com'
})

const app = express()
app.use(middleware.router())
app.listen(3000)

// Usage: curl -H "Authorization: Bearer your-secure-bearer-token-here" https://api.example.com:3000/api
```

### OAuth21 ScaleKit Authentication

```javascript
import { McpAuthMiddleware } from 'mcp-auth-middleware'
import express from 'express'

const middleware = await McpAuthMiddleware.create({
    oauth21: {
        authType: 'oauth21_scalekit',
        attachedRoutes: ['/oauth', '/secure'],
        options: {
            providerUrl: 'https://auth.scalekit.com',
            mcpId: 'res_your_mcp_id',
            clientId: 'your-scalekit-client-id',
            clientSecret: 'your-scalekit-client-secret',
            resource: 'mcp:tools:*',
            scope: 'mcp:tools:* mcp:resources:read'
        }
    },
    baseUrl: 'https://api.example.com'
})

const app = express()
app.use(middleware.router())
app.listen(3000)

// OAuth flow: Visit https://api.example.com:3000/oauth/auth/login
// Callback: https://api.example.com:3000/auth/callback (global per MCP spec)
```

### Mixed Authentication

```javascript
const middleware = await McpAuthMiddleware.create({
    staticBearer: {
        tokenSecret: 'your-bearer-token',
        attachedRoutes: ['/api/v1', '/tools']
    },
    oauth21: {
        authType: 'oauth21_scalekit',
        attachedRoutes: ['/api/v2', '/admin'],
        options: {
            providerUrl: 'https://auth.scalekit.com',
            mcpId: 'res_your_mcp_id',
            clientId: 'your-client-id',
            clientSecret: 'your-client-secret',
            resource: 'mcp:admin:*',
            scope: 'mcp:admin:* mcp:tools:*'
        }
    },
    baseUrl: 'https://api.example.com',
    forceHttps: true
})
```

## Authentication Types

### StaticBearer

Simple Bearer token authentication for internal APIs and development.

**Configuration:**
```javascript
{
    staticBearer: {
        tokenSecret: 'your-secure-token-min-8-chars',
        attachedRoutes: ['/api', '/tools', '/internal']
    }
}
```

**Required fields:**
- `tokenSecret` (string): Bearer token (minimum 8 characters, cannot start with "Bearer")
- `attachedRoutes` (array): Routes to protect with this authentication

**Usage:**
```bash
curl -H "Authorization: Bearer your-secure-token-min-8-chars" \
     https://api.example.com/api/endpoint
```

### OAuth21 ScaleKit

OAuth 2.1 implementation with ScaleKit provider support for enterprise authentication.

**Configuration:**
```javascript
{
    oauth21: {
        authType: 'oauth21_scalekit',
        attachedRoutes: ['/oauth', '/secure'],
        options: {
            providerUrl: 'https://auth.scalekit.com',
            mcpId: 'res_your_resource_id',
            clientId: 'your-scalekit-client-id',
            clientSecret: 'your-scalekit-client-secret',
            resource: 'mcp:tools:*',
            scope: 'mcp:tools:* mcp:resources:read'
        }
    }
}
```

**Required fields:**
- `authType`: Must be `'oauth21_scalekit'`
- `attachedRoutes` (array): Routes to protect with OAuth
- `options.providerUrl` (string): ScaleKit environment URL
- `options.mcpId` (string): MCP resource ID (must start with 'res_')
- `options.clientId` (string): ScaleKit client ID
- `options.clientSecret` (string): ScaleKit client secret
- `options.resource` (string): Resource identifier for MCP
- `options.scope` (string): OAuth scopes

**OAuth Endpoints:**
- `/oauth/auth/login` - Initiate OAuth flow
- `/auth/callback` - Global OAuth callback handler (one per server per MCP spec)
- `/oauth/register` - Dynamic client registration

**Discovery Endpoints (MCP Spec compliant):**
- `/.well-known/oauth-authorization-server` - Authorization server metadata
- `/.well-known/oauth-protected-resource` - Protected resource metadata
- `/.well-known/jwks.json` - JSON Web Key Set

### Mixed Authentication

Combine StaticBearer and OAuth21 for different routes:

```javascript
const middleware = await McpAuthMiddleware.create({
    staticBearer: {
        tokenSecret: 'internal-api-token',
        attachedRoutes: ['/api/internal', '/tools']
    },
    oauth21: {
        authType: 'oauth21_scalekit',
        attachedRoutes: ['/api/public', '/admin'],
        options: { /* ScaleKit config */ }
    }
})
```

## API Reference

### .create(options)

Creates a new MCP OAuth middleware instance.

**Parameters:**

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| staticBearer | object | StaticBearer authentication config | No |
| oauth21 | object | OAuth21 authentication config | No |
| silent | boolean | Suppress console output | No |
| baseUrl | string | Base URL for redirects and metadata | No |
| forceHttps | boolean | Require HTTPS for OAuth endpoints | No |

**Returns:** `Promise<McpAuthMiddleware>`

**Example:**
```javascript
const middleware = await McpAuthMiddleware.create({
    staticBearer: {
        tokenSecret: 'secure-token',
        attachedRoutes: ['/api']
    },
    silent: true,
    baseUrl: 'https://api.example.com'
})
```

### .router()

Returns Express router middleware.

**Returns:** `Express Router`

**Example:**
```javascript
const app = express()
app.use(middleware.router())
```

### .getRoutes()

Returns array of all protected route paths.

**Returns:** `string[]`

**Example:**
```javascript
const routes = middleware.getRoutes()
// → ['/api', '/tools', '/oauth']
```

### .getRouteConfig({ routePath })

Returns configuration for a specific route.

**Parameters:**

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| routePath | string | Route path to get config for | Yes |

**Returns:** `object | undefined`

**Example:**
```javascript
const config = middleware.getRouteConfig({ routePath: '/api' })
console.log(config.authType) // → 'staticBearer'
```

## Migration Guide

### From v0.x to v1.0

**Step 1: Update API structure**

❌ **Old (v0.x):**
```javascript
await McpAuthMiddleware.create({
    routes: {
        '/api': {
            authType: 'oauth21_auth0',
            providerUrl: 'https://tenant.auth0.com',
            clientId: 'client-id',
            clientSecret: 'client-secret',
            scope: 'openid profile',
            audience: 'https://api.example.com',
            realm: 'api-realm',
            requiredScopes: ['openid', 'profile'],
            requiredRoles: ['user']
        },
        '/tools': {
            authType: 'staticBearer',
            token: 'bearer-token',
            realm: 'tools-realm'
        }
    }
})
```

✅ **New (v1.0):**
```javascript
await McpAuthMiddleware.create({
    staticBearer: {
        tokenSecret: 'bearer-token',
        attachedRoutes: ['/tools']
    },
    oauth21: {
        authType: 'oauth21_scalekit',
        attachedRoutes: ['/api'],
        options: {
            providerUrl: 'https://auth.scalekit.com',
            mcpId: 'res_your_id',
            clientId: 'client-id',
            clientSecret: 'client-secret',
            resource: 'mcp:tools:*',
            scope: 'mcp:tools:* mcp:resources:read'
        }
    }
})
```

**Step 2: Update provider configuration**

- **Auth0 → ScaleKit:** Auth0 support has been removed. Migrate to ScaleKit OAuth21
- **Token field:** `token` → `tokenSecret` for StaticBearer
- **Route structure:** Individual route configs → `attachedRoutes` arrays
- **Discovery endpoints:** Route-specific → Root-level only

**Step 3: Update environment variables**

Remove Auth0 variables, add ScaleKit:
```env
# Remove these (Auth0)
# AUTH0_DOMAIN=tenant.auth0.com
# AUTH0_CLIENT_ID=...
# AUTH0_CLIENT_SECRET=...

# Add these (ScaleKit)
SCALEKIT_ENVIRONMENT_URL=https://auth.scalekit.com
SCALEKIT_CLIENT_ID=your_client_id
SCALEKIT_CLIENT_SECRET=your_client_secret
SCALEKIT_MCP_ID=res_your_resource_id
```

**Step 4: Update discovery endpoint URLs**

- **Old:** `/route/.well-known/oauth-authorization-server`
- **New:** `/.well-known/oauth-authorization-server` (root level)

## Testing

Run the complete test suite:

```bash
# All tests
npm test

# Test coverage
npm run test:coverage:src

# Specific test file
npm run test:file tests/unit/index.test.js
```

**Test Results (v1.0):**
- ✅ 11 test suites passing
- ✅ 204 tests passing
- ✅ 0 failing tests
- ✅ Tool testing with MCP session management
- ✅ Global OAuth callback architecture

**Manual testing:**

```bash
# Run reference implementation with OAuth testing
node tests/manual/2-reference-dynamic-implmentation.mjs --routeType=oauth

# Test StaticBearer flow
npm run test:local:bearer

# Test OAuth flow with tool execution
npm run test:local:oauth

# Test free route (no authentication)
npm run test:local:free
```

## License

MIT © [Your Name]

---

📚 **Documentation for MCP (Model Context Protocol) compliance and ScaleKit integration available in the `/docs` folder.**