# Multi-Realm OAuth 2.1 Middleware for MCP Servers

[![Test](https://img.shields.io/github/actions/workflow/status/flowmcp/oauth-middleware/test-on-release.yml)]() ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Express-compatible **multi-realm OAuth 2.1 middleware** for securing MCP server endpoints with Auth0 and multi-provider authentication.

## Installation

```bash
npm install
```

## Usage

```javascript
import { McpAuthMiddleware } from './src/index.mjs'
import express from 'express'

const middleware = await McpAuthMiddleware.create({
    routes: {
        '/api': {
            authType: 'oauth21_auth0',
            providerUrl: 'https://your-domain.auth0.com',
            clientId: 'your-client-id',
            clientSecret: 'your-client-secret',
            scope: 'openid profile email',
            audience: 'https://your-api.example.com',
            requiredScopes: ['openid', 'profile'],
            forceHttps: true
        }
    }
})

const app = express()
app.use(middleware.router())
app.listen(3000)
```

## Features

✅ **Multi-AuthType Support** - Flexible authentication system  
✅ **OAuth 2.1 Compliance** - PKCE, secure flows, modern standards  
✅ **Auth0 Integration** - Ready-to-use Auth0 provider implementation  
✅ **Multi-Realm Architecture** - Different auth configs per route  
✅ **Express Compatible** - Standard middleware integration  
✅ **Comprehensive Testing** - 396 tests, 88.96% coverage  

## Supported AuthTypes

### `oauth21_auth0`
OAuth 2.1 implementation for Auth0 provider with PKCE support.

**Required fields:**
- `providerUrl` - Auth0 domain URL (e.g., `https://tenant.auth0.com`)
- `clientId` - Auth0 application client ID
- `clientSecret` - Auth0 application client secret  
- `scope` - OAuth scopes to request (e.g., `openid profile email`)
- `audience` - Auth0 API audience identifier

**Optional fields:**
- `redirectUri` - Custom OAuth redirect URI
- `requiredScopes` - Array of scopes required for protected routes
- `forceHttps` - Enforce HTTPS for OAuth endpoints (default: true)

## API

### `.create({ routes })`
Creates middleware instance with route-to-AuthType mapping.

**Parameters:**
- `routes` - Object mapping route paths to AuthType configurations
- `silent` - Optional boolean to suppress logging (default: false)

### `.router()`
Returns Express router with OAuth endpoints and protection middleware.

### `.getRoutes()`
Returns array of configured route paths.

### `.getRouteConfig(route)`
Returns AuthType configuration for specific route path.

### `.getRealms()`
Returns array of configured realms across all routes.


## Testing

```bash
npm test
npm run test:coverage:src
```

## License

MIT - see [LICENSE](LICENSE) file for details.