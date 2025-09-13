# MCP OAuth Middleware

[![Test](https://img.shields.io/github/actions/workflow/status/flowmcp/oauth-middleware/test-on-release.yml)]() ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Express-compatible authentication middleware for securing MCP server endpoints with OAuth 2.1 and Bearer token support.

## Table of Contents

- [MCP OAuth Middleware](#mcp-oauth-middleware)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [AuthTypes](#authtypes)
    - [oauth21\_auth0](#oauth21_auth0)
    - [staticBearer](#staticbearer)
  - [Configuration](#configuration)
    - [Multi-Route Setup](#multi-route-setup)
  - [API Reference](#api-reference)
    - [.create({ routes, silent })](#create-routes-silent-)
    - [.router()](#router)
    - [.getRoutes()](#getroutes)
    - [.getRouteConfig({ routePath })](#getrouteconfigroutepath)
  - [Testing](#testing)
  - [License](#license)

## Installation

```bash
npm install
```

## Quick Start

```javascript
import { McpAuthMiddleware } from './src/index.mjs'
import express from 'express'

const middleware = await McpAuthMiddleware.create({
    routes: {
        '/api/oauth': {
            authType: 'oauth21_auth0',
            providerUrl: 'https://your-domain.auth0.com',
            clientId: 'your-client-id',
            clientSecret: 'your-client-secret',
            scope: 'openid profile email',
            audience: 'https://your-api.example.com',
            realm: 'api-realm',
            authFlow: 'authorization_code',
            requiredScopes: ['openid', 'profile', 'email'],
            requiredRoles: ['user']
        },
        '/api/simple': {
            authType: 'staticBearer',
            token: 'your-secure-token-here',
            realm: 'simple-realm'
        }
    }
})

const app = express()
app.use(middleware.router())
app.listen(3000)
```

## AuthTypes

### oauth21_auth0

OAuth 2.1 implementation with Auth0 provider support.

**Configuration:**
```javascript
{
    authType: 'oauth21_auth0',
    providerUrl: 'https://tenant.auth0.com',
    clientId: 'your-auth0-client-id',
    clientSecret: 'your-auth0-client-secret',
    scope: 'openid profile email',
    audience: 'https://your-api.example.com',
    realm: 'api-realm',
    authFlow: 'authorization_code',
    requiredScopes: ['openid', 'profile', 'email'],
    requiredRoles: ['user']
}
```

**Required fields:**
- `authType` - Must be 'oauth21_auth0'
- `providerUrl` - Auth0 domain URL (must contain 'auth0.com')
- `clientId` - Auth0 application client ID
- `clientSecret` - Auth0 application client secret
- `scope` - OAuth scopes to request (string)
- `audience` - Auth0 API audience identifier (string)
- `realm` - Security realm identifier
- `authFlow` - OAuth flow type (typically 'authorization_code')
- `requiredScopes` - Array of required scopes for access
- `requiredRoles` - Array of required roles for access

**Optional fields:**
- `redirectUri` - Custom OAuth redirect URI
- `forceHttps` - Enforce HTTPS (default: true)
- `resourceUri` - Resource URI for OAuth resource indicators

### staticBearer

Simple static Bearer token authentication.

**Configuration:**
```javascript
{
    authType: 'staticBearer',
    token: 'your-secure-token-minimum-8-chars',
    realm: 'bearer-realm'
}
```

**Required fields:**
- `authType` - Must be 'staticBearer'
- `token` - Static Bearer token (minimum 8 characters, no "Bearer" prefix)
- `realm` - Security realm identifier

## Configuration

### Multi-Route Setup

```javascript
const middleware = await McpAuthMiddleware.create({
    routes: {
        '/admin': {
            authType: 'oauth21_auth0',
            providerUrl: 'https://admin.auth0.com',
            clientId: 'admin-client-id',
            clientSecret: 'admin-secret',
            scope: 'openid profile email admin:read',
            audience: 'https://api.example.com/admin',
            realm: 'admin-realm',
            authFlow: 'authorization_code',
            requiredScopes: ['openid', 'profile', 'email', 'admin:read'],
            requiredRoles: ['admin']
        },
        '/api/public': {
            authType: 'staticBearer',
            token: 'public-api-token-12345678',
            realm: 'public-realm'
        },
        '/api/internal': {
            authType: 'staticBearer',
            token: 'internal-secure-token-87654321',
            realm: 'internal-realm'
        }
    },
    silent: false
})
```

## API Reference

### .create({ routes, silent })

Creates middleware instance with route-to-AuthType mapping.

**Parameters:**
- `routes` - Object mapping route paths to AuthType configurations
- `silent` - Boolean to suppress logging (default: false)

**Returns:** Middleware instance

### .router()

Returns Express router with OAuth endpoints and protection middleware.

**Returns:** Express Router

### .getRoutes()

Returns array of configured route paths.

**Returns:** Array of strings

### .getRouteConfig({ routePath })

Returns AuthType configuration for specific route path.

**Parameters:**
- `routePath` - Route path string

**Returns:** Configuration object



## Testing

```bash
npm test
npm run test:coverage:src
```

## License

MIT - see [LICENSE](LICENSE) file for details.