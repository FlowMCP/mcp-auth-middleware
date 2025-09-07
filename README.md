# Multi-Realm OAuth 2.1 Middleware for MCP Servers

[![Test](https://img.shields.io/github/actions/workflow/status/flowmcp/oauth-middleware/test-on-release.yml)]() ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An Express-compatible **multi-realm OAuth 2.1 middleware** designed for securing Model Context Protocol (MCP) server endpoints with industry-standard authentication and multiple Keycloak realm support.

## Overview

This middleware provides a powerful **multi-realm OAuth 2.1** authentication solution for MCP servers, enabling different routes to authenticate against different Keycloak realms with route-specific scope requirements. It implements secure authorization code flows with PKCE, automatic discovery endpoints, and comprehensive RFC compliance.

> **Transport Support:** This middleware is designed for **HTTP + SSE (Server-Sent Events)** transport, making it ideal for remote MCP servers and web-based clients. It does **not** support stdio transport used by local MCP servers in Claude Desktop.

## Key Features

### 🏛️ Multi-Realm Architecture
- **Route-to-Realm Mapping** - Different endpoints can use different Keycloak realms
- **Route-Specific Scopes** - Each route can have its own scope requirements
- **Automatic URL Generation** - OAuth endpoints auto-generated per realm
- **Centralized Management** - Single middleware instance manages multiple realms

### 🛡️ OAuth 2.1 & RFC Compliance
- **OAuth 2.1 Security Standards** - HTTPS enforcement, PKCE required, Bearer tokens only
- **RFC 8414** - OAuth 2.0 Authorization Server Metadata discovery
- **RFC 9728** - Protected Resource Metadata with route-specific information
- **RFC 8707** - Resource Indicators for audience binding validation
- **Dynamic Client Registration** - RFC 7591 compliant automatic client setup

### 🚀 Production Features
- **Express Integration** - Drop-in middleware for Express applications
- **MCP Server Support** - Native FlowMCP RemoteServer integration with SSE transport
- **Automatic JWKS Aggregation** - Combines JWKS from all configured realms
- **Discovery Endpoints** - Well-known OAuth metadata endpoints
- **Comprehensive Testing** - 49 unit tests covering all functionality
- **Live Demo Server** - Multi-realm demonstration included

## Quick Start

### Installation

```bash
git clone https://github.com/flowmcp/oauth-middleware.git
cd oauth-middleware
npm install
```

### Multi-Realm Configuration

```javascript
import { OAuthMiddleware } from './src/index.mjs'
import express from 'express'

// Create multi-realm OAuth middleware
const middleware = await OAuthMiddleware.create({
    realmsByRoute: {
        '/api': {
            keycloakUrl: 'http://localhost:8080',
            realm: 'api-realm',
            clientId: 'api-client',
            clientSecret: process.env.API_CLIENT_SECRET,
            requiredScopes: ['api:read', 'api:write'],
            resourceUri: 'http://localhost:3000/api'
        },
        '/admin': {
            keycloakUrl: 'http://localhost:8080', 
            realm: 'admin-realm',
            clientId: 'admin-client',
            clientSecret: process.env.ADMIN_CLIENT_SECRET,
            requiredScopes: ['admin:full'],
            resourceUri: 'http://localhost:3000/admin'
        },
        '/public': {
            keycloakUrl: 'http://localhost:8080',
            realm: 'public-realm', 
            clientId: 'public-client',
            clientSecret: process.env.PUBLIC_CLIENT_SECRET,
            requiredScopes: ['user:basic'],
            resourceUri: 'http://localhost:3000/public'
        }
    }
})

const app = express()

// Add OAuth middleware (handles all OAuth endpoints and protection)
app.use(middleware.router())

// Your protected routes
app.get('/api/data', (req, res) => {
    // Protected by api-realm, requires ['api:read', 'api:write'] scopes
    res.json({ message: 'API data', user: req.oauth })
})

app.get('/admin/users', (req, res) => {
    // Protected by admin-realm, requires ['admin:full'] scope  
    res.json({ message: 'Admin users', user: req.oauth })
})

app.get('/public/info', (req, res) => {
    // Protected by public-realm, requires ['user:basic'] scope
    res.json({ message: 'Public info', user: req.oauth })
})

app.listen(3000, () => {
    console.log('Multi-realm OAuth server running on http://localhost:3000')
})
```

### MCP Server Integration

```javascript
import { RemoteServer } from 'flowmcpServers'
import { OAuthMiddleware } from './src/index.mjs'

// Create multi-realm middleware for MCP endpoints
const middleware = await OAuthMiddleware.create({
    realmsByRoute: {
        '/mcp': {
            keycloakUrl: 'http://localhost:8080',
            realm: 'mcp-realm',
            clientId: 'mcp-client', 
            clientSecret: process.env.MCP_CLIENT_SECRET,
            requiredScopes: ['mcp:access'],
            resourceUri: 'http://localhost:3000/mcp'
        }
    }
})

// Create MCP server with OAuth protection
const server = RemoteServer.create({
    middleware: middleware.router(),
    transport: 'sse'
})

// All /mcp/* endpoints are now protected by mcp-realm
server.listen(3000)
```

## Multi-Realm Architecture

The middleware automatically creates the following structure:

### Route-Specific OAuth Endpoints

Each configured route gets its own OAuth flow endpoints:

```
/api/auth/login      → Start OAuth flow for API realm
/api/auth/callback   → OAuth callback for API realm
/admin/auth/login    → Start OAuth flow for Admin realm  
/admin/auth/callback → OAuth callback for Admin realm
/public/auth/login   → Start OAuth flow for Public realm
/public/auth/callback → OAuth callback for Public realm
```

### Discovery Endpoints (RFC Compliant)

Automatically generated metadata endpoints:

```
/.well-known/oauth-authorization-server         → Gateway metadata (RFC 8414)
/.well-known/jwks.json                         → Aggregated JWKS from all realms
/.well-known/oauth-protected-resource/api      → API resource metadata (RFC 9728)
/.well-known/oauth-protected-resource/admin    → Admin resource metadata (RFC 9728)
/.well-known/oauth-protected-resource/public   → Public resource metadata (RFC 9728)  
```

### Realm Configuration

Each realm in `realmsByRoute` supports:

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `keycloakUrl` | string | Keycloak server URL | Yes |
| `realm` | string | Keycloak realm name | Yes |
| `clientId` | string | OAuth client ID | Yes |
| `clientSecret` | string | OAuth client secret | Yes |
| `requiredScopes` | string[] | Required scopes for this route | Yes |
| `resourceUri` | string | Resource URI for audience binding (RFC 8707) | Yes |

## OAuth 2.1 Security Features

### HTTPS Enforcement
- **Production**: All endpoints require HTTPS
- **Development**: Automatic bypass for localhost/127.0.0.1

### Bearer Token Security  
- **Header Only**: Tokens must be in `Authorization: Bearer <token>` header
- **URL Forbidden**: Tokens in URL parameters are rejected (OAuth 2.1 requirement)
- **Format Validation**: Strict Bearer token format enforcement

### PKCE (Proof Key for Code Exchange)
- **Required**: All authorization flows use PKCE with S256 method
- **Auto-Generated**: Code challenge/verifier pairs created automatically
- **Security**: Protects against authorization code interception

## API Methods

### `.create({ realmsByRoute })`

Creates a new multi-realm OAuth middleware instance.

**Parameters:**
- `realmsByRoute` (object): Route-to-realm mapping configuration

**Example:**
```javascript
const middleware = await OAuthMiddleware.create({
    realmsByRoute: {
        '/api': { /* realm config */ },
        '/admin': { /* realm config */ }
    }
})
```

**Returns:**
```javascript
{
    router(): ExpressRouter,    // Express router with all OAuth endpoints
    getRoutes(): string[],      // Get all configured routes
    getRealms(): object[],      // Get all realm configurations
    getRouteConfig(route): object  // Get config for specific route
}
```

### `.router()`

Returns the Express router containing all OAuth endpoints and middleware.

**Example:**
```javascript
const app = express()
app.use(middleware.router())  // Adds all OAuth endpoints and protection
```

### `.getRoutes()`

Returns array of all configured routes.

**Example:**
```javascript
const routes = middleware.getRoutes()
// Returns: ['/api', '/admin', '/public']
```

### `.getRealms()`

Returns detailed information about all configured realms.

**Example:**
```javascript
const realms = middleware.getRealms()
// Returns: [{ route: '/api', realm: 'api-realm', ... }]
```

### `.getRouteConfig(route)`

Returns configuration for a specific route.

**Example:**
```javascript
const config = middleware.getRouteConfig('/api')
// Returns: { keycloakUrl: '...', realm: 'api-realm', ... }
```

## Request Context

Protected endpoints receive OAuth context via `req.oauth`:

```javascript
app.get('/protected', (req, res) => {
    console.log('OAuth Context:', req.oauth)
    // {
    //   user: { sub: 'user-id', preferred_username: 'user', ... },
    //   scopes: ['api:read', 'api:write'],
    //   route: '/api',
    //   realm: 'api-realm',
    //   clientId: 'api-client'
    // }
})
```

## Testing & Demo

### Run Test Suite

```bash
npm test                    # Run all tests (49 tests)
npm run test:coverage:src   # Run with coverage report  
```

### Multi-Realm Demo Server

```bash
node tests/manual/multi-realm-demo.mjs
```

The demo server showcases:
- 3 protected routes with different realms
- All discovery endpoints  
- OAuth flow endpoints
- RFC compliance validation
- Live testing endpoints

## Migration from Single-Realm

If upgrading from a single-realm setup:

### Before (Single-Realm)
```javascript
const middleware = OAuthMiddleware.create({
    keycloakUrl: 'http://localhost:8080',
    realm: 'my-realm', 
    clientId: 'my-client',
    clientSecret: 'my-secret'
})
```

### After (Multi-Realm)
```javascript
const middleware = await OAuthMiddleware.create({
    realmsByRoute: {
        '/': {  // Root route for backward compatibility
            keycloakUrl: 'http://localhost:8080',
            realm: 'my-realm',
            clientId: 'my-client', 
            clientSecret: 'my-secret',
            requiredScopes: ['access'],  // Now required
            resourceUri: 'http://localhost:3000'  // Now required
        }
    }
})
```

### Breaking Changes
- **API Change**: `OAuthMiddleware.create()` now requires `realmsByRoute` object
- **Async**: Middleware creation is now `async` (use `await`)
- **Required Fields**: `requiredScopes` and `resourceUri` are now mandatory
- **Method Removal**: `.mcp()`, `.mcpWithRBAC()`, `.wellKnownXxx()` methods removed (handled by router)

## RFC Compliance

This middleware implements the following RFC standards:

### RFC 8414 - OAuth 2.0 Authorization Server Metadata
- Gateway metadata endpoint aggregates all realm information
- Standard discovery at `/.well-known/oauth-authorization-server`
- Multi-realm extensions for route-to-realm mapping

### RFC 9728 - OAuth 2.0 Protected Resource Metadata  
- Route-specific resource metadata endpoints
- Audience binding information for each protected resource
- Standard discovery at `/.well-known/oauth-protected-resource/{route}`

### RFC 8707 - OAuth 2.0 Resource Indicators
- Resource parameters included in all OAuth flows
- Audience binding validation for access tokens
- Support for resource-specific token issuance

### OAuth 2.1 Security Profile
- HTTPS enforcement for all endpoints
- PKCE required for all authorization flows
- Bearer token format enforcement
- URL parameter token prohibition

## Environment Variables

For development and testing:

```bash
# Keycloak Configuration
KEYCLOAK_URL=http://localhost:8080

# API Realm
API_REALM=api-realm
API_CLIENT_ID=api-client
API_CLIENT_SECRET=your-api-secret

# Admin Realm  
ADMIN_REALM=admin-realm
ADMIN_CLIENT_ID=admin-client
ADMIN_CLIENT_SECRET=your-admin-secret

# Public Realm
PUBLIC_REALM=public-realm
PUBLIC_CLIENT_ID=public-client
PUBLIC_CLIENT_SECRET=your-public-secret
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`npm test`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/flowmcp/oauth-middleware/issues)
- **Documentation**: This README and inline code documentation
- **Examples**: See `tests/manual/multi-realm-demo.mjs` for complete working examples