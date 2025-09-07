# Multi-Realm OAuth 2.1 Middleware for MCP Servers

[![Test](https://img.shields.io/github/actions/workflow/status/flowmcp/oauth-middleware/test-on-release.yml)]() ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Express-compatible **multi-realm OAuth 2.1 middleware** for securing MCP server endpoints with Keycloak authentication.

## Installation

```bash
npm install
```

## Usage

```javascript
import { OAuthMiddleware } from './src/index.mjs'
import express from 'express'

const middleware = await OAuthMiddleware.create({
    realmsByRoute: {
        '/api': {
            keycloakUrl: 'http://localhost:8080',
            realm: 'api-realm',
            clientId: 'api-client',
            clientSecret: 'secret',
            requiredScopes: ['api:read'],
            resourceUri: 'http://localhost:3000/api'
        }
    }
})

const app = express()
app.use(middleware.router())
app.listen(3000)
```

## API

### `.create({ realmsByRoute })`
Creates middleware instance with route-to-realm mapping.

### `.router()`
Returns Express router with OAuth endpoints and protection.

### `.getRoutes()`
Returns array of configured routes.

### `.getRouteConfig(route)`
Returns configuration for specific route.

## Testing

```bash
npm test
npm run test:coverage:src
```

## License

MIT - see [LICENSE](LICENSE) file for details.