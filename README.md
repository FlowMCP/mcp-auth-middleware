# OAuth Middleware for MCP Servers

[![Test](https://img.shields.io/github/actions/workflow/status/flowmcp/oauth-middleware/test-on-release.yml)]() ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Description

A comprehensive OAuth 2.1 middleware for Model Context Protocol (MCP) servers with full Keycloak integration. This middleware provides secure authentication and authorization for MCP servers, implementing the latest OAuth 2.1 standards including PKCE, Dynamic Client Registration, and Resource Indicators.

## Features

- **OAuth 2.1 Compliant** - Full implementation of OAuth 2.1 with PKCE mandatory
- **Authorization Code Flow** - Secure authorization with PKCE protection
- **Client Credentials Flow** - Service-to-service authentication
- **Dynamic Client Registration** - RFC 7591 compliant automatic client registration
- **Resource Indicators** - RFC 8707 implementation for fine-grained access
- **Refresh Token Support** - Seamless token renewal
- **RBAC Support** - Role-Based Access Control with method-level authorization
- **Well-Known Endpoints** - OAuth discovery metadata endpoints
- **Express.js Compatible** - Easy integration with Express applications
- **JWT Validation** - Secure token validation with JWKS support
- **Keycloak Integration** - Native support for Keycloak identity management

## Quickstart 

### Installation

```bash
git clone https://github.com/flowmcp/oauth-middleware.git
cd oauth-middleware
npm install
```

### Basic Usage

```javascript
import { OAuthMiddleware } from 'oauth-middleware-mcp'
import express from 'express'

const app = express()

// Create OAuth middleware
const { middleware } = OAuthMiddleware.create( {
    keycloakUrl: 'https://oauth.flowmcp.org',
    realm: 'mcp-realm',
    clientId: 'mcp-server-client',
    clientSecret: process.env.CLIENT_SECRET,
    redirectUri: 'http://localhost:3000/callback'
} )

// Use as Express middleware
app.use( middleware.mcp() )

// Or use with RBAC
app.use( middleware.mcpWithRBAC() )

app.listen( 3000 )
```

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [API Methods](#api-methods)
- [OAuth Flows](#oauth-flows)
- [RBAC Configuration](#rbac-configuration)
- [Well-Known Endpoints](#well-known-endpoints)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Configuration

### Environment Variables

```env
KEYCLOAK_URL=https://oauth.flowmcp.org
KEYCLOAK_REALM=mcp-realm
KEYCLOAK_CLIENT_ID=mcp-server-client
KEYCLOAK_CLIENT_SECRET=your-client-secret
REDIRECT_URI=http://localhost:3000/callback
```

### Middleware Configuration

```javascript
const { middleware } = OAuthMiddleware.create( {
    keycloakUrl: process.env.KEYCLOAK_URL,
    realm: process.env.KEYCLOAK_REALM,
    clientId: process.env.KEYCLOAK_CLIENT_ID,
    clientSecret: process.env.KEYCLOAK_CLIENT_SECRET,
    redirectUri: process.env.REDIRECT_URI,
    silent: false  // Enable logging
} )
```

## API Methods

### `.create()`

Creates a new OAuth middleware instance.

**Method**
```javascript
.create( { keycloakUrl, realm, clientId, clientSecret, redirectUri, silent } )
```

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| keycloakUrl | string | Keycloak server URL | Yes |
| realm | string | Keycloak realm name | Yes |
| clientId | string | OAuth client ID | Yes |
| clientSecret | string | OAuth client secret | No |
| redirectUri | string | OAuth redirect URI | No |
| silent | boolean | Suppress console output | No |

**Returns**
```javascript
{ middleware }
```

### `.mcp()`

Returns Express middleware for basic OAuth protection.

**Method**
```javascript
.mcp()
```

**Example**
```javascript
app.use( '/api', middleware.mcp() )
```

**Returns**
Express middleware function

### `.mcpWithRBAC()`

Returns Express middleware with Role-Based Access Control.

**Method**
```javascript
.mcpWithRBAC()
```

**Example**
```javascript
middleware.setRBACRules( { rules: rbacRules } )
app.use( '/api', middleware.mcpWithRBAC() )
```

**Returns**
Express middleware function with RBAC enforcement

### `.initiateAuthorizationCodeFlow()`

Initiates OAuth 2.1 Authorization Code Flow with PKCE.

**Method**
```javascript
.initiateAuthorizationCodeFlow( { scopes, resourceIndicators } )
```

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| scopes | array | OAuth scopes to request | No |
| resourceIndicators | array | Resource indicators (RFC 8707) | No |

**Example**
```javascript
const { authorizationUrl, state } = middleware.initiateAuthorizationCodeFlow( {
    scopes: [ 'openid', 'mcp:tools' ],
    resourceIndicators: [ 'https://api.example.com' ]
} )
```

**Returns**
```javascript
{ authorizationUrl, state }
```

### `.handleAuthorizationCallback()`

Handles OAuth authorization callback and exchanges code for tokens.

**Method**
```javascript
.handleAuthorizationCallback( { code, state } )
```

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| code | string | Authorization code from callback | Yes |
| state | string | State parameter from callback | Yes |

**Returns**
```javascript
{ success, tokens }
```

### `.requestClientCredentials()`

Requests access token using Client Credentials flow.

**Method**
```javascript
.requestClientCredentials( { scopes } )
```

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| scopes | array | OAuth scopes to request | No |

**Returns**
```javascript
{ tokens }
```

### `.refreshAccessToken()`

Refreshes access token using refresh token.

**Method**
```javascript
.refreshAccessToken( { refreshToken } )
```

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| refreshToken | string | Refresh token | Yes |

**Returns**
```javascript
{ success, tokens }
```

### `.registerClient()`

Dynamically registers a new OAuth client (RFC 7591).

**Method**
```javascript
.registerClient( { clientName, redirectUris, grantTypes } )
```

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| clientName | string | Name for the new client | Yes |
| redirectUris | array | Redirect URIs for the client | Yes |
| grantTypes | array | OAuth grant types | No |

**Returns**
```javascript
{ 
    success, 
    clientId, 
    clientSecret, 
    registrationAccessToken,
    metadata 
}
```

### `.setRBACRules()`

Configures Role-Based Access Control rules.

**Method**
```javascript
.setRBACRules( { rules } )
```

| Key | Type | Description | Required |
|-----|------|-------------|----------|
| rules | array | Array of RBAC rule objects | Yes |

**Example**
```javascript
const rules = [
    {
        path: '/api/admin',
        methods: [ 'GET', 'POST' ],
        requiredRoles: [ 'admin' ],
        requiredScopes: [ 'mcp:admin' ]
    },
    {
        path: '/api/weather',
        requiredScopes: [ 'mcp:tools:weather' ]
    }
]

middleware.setRBACRules( { rules } )
```

### `.checkRBAC()`

Checks if access is allowed based on RBAC rules.

**Method**
```javascript
.checkRBAC( { path, method, roles, scopes } )
```

**Returns**
```javascript
{ allowed, reason }
```

## OAuth Flows

### Authorization Code Flow with PKCE

```javascript
// Step 1: Initiate authorization
const { authorizationUrl, state } = middleware.initiateAuthorizationCodeFlow( {
    scopes: [ 'openid', 'profile', 'mcp:tools' ]
} )

// Redirect user to authorizationUrl

// Step 2: Handle callback
app.get( '/callback', async ( req, res ) => {
    const { code, state } = req.query
    
    const { success, tokens } = await middleware.handleAuthorizationCallback( {
        code,
        state
    } )
    
    if( success ) {
        // Store tokens securely
        res.json( { access_token: tokens.access_token } )
    }
} )
```

### Client Credentials Flow

```javascript
const { tokens } = await middleware.requestClientCredentials( {
    scopes: [ 'mcp:tools' ]
} )

console.log( 'Access Token:', tokens.access_token )
```

### Token Refresh

```javascript
const { success, tokens } = await middleware.refreshAccessToken( {
    refreshToken: storedRefreshToken
} )

if( success ) {
    // Update stored tokens
    updateTokens( tokens )
}
```

## RBAC Configuration

### Define Access Rules

```javascript
const rbacRules = [
    // Admin-only endpoints
    {
        path: '/api/admin/*',
        methods: [ 'GET', 'POST', 'PUT', 'DELETE' ],
        requiredRoles: [ 'admin', 'super-admin' ]
    },
    
    // Tool-specific access
    {
        path: '/api/tools/weather',
        requiredScopes: [ 'mcp:tools:weather' ]
    },
    
    // Combined role and scope requirement
    {
        path: '/api/sensitive',
        methods: [ 'POST' ],
        requiredRoles: [ 'verified-user' ],
        requiredScopes: [ 'mcp:resources:write' ]
    }
]

middleware.setRBACRules( { rules: rbacRules } )
```

### Using RBAC Middleware

```javascript
app.use( middleware.mcpWithRBAC() )

// Access user information in routes
app.get( '/api/profile', ( req, res ) => {
    res.json( {
        user: req.user,
        roles: req.roles,
        scopes: req.scopes
    } )
} )
```

## Well-Known Endpoints

The middleware provides OAuth 2.1 discovery endpoints:

```javascript
// Authorization Server Metadata
app.get( '/.well-known/oauth-authorization-server', 
    middleware.wellKnownAuthorizationServer() 
)

// Protected Resource Metadata
app.get( '/.well-known/oauth-protected-resource', 
    middleware.wellKnownProtectedResource() 
)

// JSON Web Key Set
app.get( '/.well-known/jwks.json', 
    middleware.wellKnownJwks() 
)
```

## Examples

### Complete Express Application

```javascript
import express from 'express'
import { OAuthMiddleware } from 'oauth-middleware-mcp'

const app = express()

// Initialize middleware
const { middleware } = OAuthMiddleware.create( {
    keycloakUrl: 'https://oauth.flowmcp.org',
    realm: 'mcp-realm',
    clientId: 'mcp-server',
    clientSecret: process.env.CLIENT_SECRET,
    redirectUri: 'http://localhost:3000/callback'
} )

// Configure RBAC
middleware.setRBACRules( {
    rules: [
        {
            path: '/api/admin',
            requiredRoles: [ 'admin' ]
        },
        {
            path: '/api/tools',
            requiredScopes: [ 'mcp:tools' ]
        }
    ]
} )

// Public endpoints
app.get( '/', ( req, res ) => {
    res.send( 'Public endpoint' )
} )

// Protected endpoints
app.use( '/api', middleware.mcpWithRBAC() )

app.get( '/api/data', ( req, res ) => {
    res.json( { 
        message: 'Protected data',
        user: req.user.sub 
    } )
} )

app.listen( 3000, () => {
    console.log( 'Server running on http://localhost:3000' )
} )
```

### MCP Server Integration

```javascript
import { RemoteServer } from 'mcpServers'
import { OAuthMiddleware } from 'oauth-middleware-mcp'

const { middleware } = OAuthMiddleware.create( {
    keycloakUrl: 'https://oauth.flowmcp.org',
    realm: 'mcp-realm',
    clientId: 'mcp-server',
    clientSecret: process.env.CLIENT_SECRET
} )

const remoteServer = new RemoteServer( { silent: false } )
const app = remoteServer.getApp()

// Apply OAuth protection to all MCP endpoints
app.use( middleware.mcp() )

// Start MCP server
remoteServer.start()
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions, please use the [GitHub Issues](https://github.com/flowmcp/oauth-middleware/issues) page.

## Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io/)
- Powered by [Keycloak](https://www.keycloak.org/)
- Following OAuth 2.1 standards