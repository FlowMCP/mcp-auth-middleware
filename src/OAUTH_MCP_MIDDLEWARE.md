# OAuth MCP Middleware - Technical Documentation

## Architecture Overview

The OAuth MCP Middleware is a **multi-realm OAuth 2.1 authentication middleware** specifically designed for Model Context Protocol (MCP) servers. It provides enterprise-grade security through Keycloak integration while maintaining RFC compliance and OAuth 2.1 security standards.

### Core Design Principles

1. **Multi-Realm Architecture**: Different routes can authenticate against different Keycloak realms
2. **RFC Compliance**: Strict adherence to OAuth 2.0/2.1 specifications
3. **Security First**: PKCE mandatory, Bearer-only tokens, HTTPS enforcement
4. **MCP Optimized**: Built for HTTP+SSE transport used by remote MCP servers

## Capabilities & Limitations

### What This Module DOES

✅ **Multi-Realm OAuth Protection**
- Route-to-realm mapping for different security contexts
- Per-route scope requirements
- Automatic OAuth endpoint generation per realm

✅ **RFC-Compliant Discovery**
- OAuth 2.0 Authorization Server Metadata (RFC 8414)
- Protected Resource Metadata (RFC 9728)
- Resource Indicators (RFC 8707)
- Aggregated JWKS from all realms

✅ **Security Features**
- PKCE (S256) for all authorization flows
- Bearer token validation (header-only)
- Automatic token introspection
- HTTPS enforcement in production

✅ **Express Integration**
- Drop-in Express middleware
- Automatic route protection
- Request context enrichment

### What This Module DOES NOT

❌ **Transport Limitations**
- No stdio transport support (local MCP servers)
- No WebSocket support
- HTTP + SSE only

❌ **Authentication Methods**
- No Basic Auth
- No API Key authentication
- No mTLS support
- OAuth 2.1 Bearer tokens only

❌ **Token Management**
- No token refresh handling (client responsibility)
- No token storage/persistence
- No session management

## RFC Specifications

### OAuth 2.1 (draft-ietf-oauth-v2-1)
- **HTTPS Required**: All endpoints must use TLS in production
- **PKCE Mandatory**: Code challenge required for all flows
- **Bearer Only**: Tokens must be in Authorization header
- **No URL Tokens**: Query parameter tokens prohibited

### RFC 8414 - Authorization Server Metadata
```
GET /.well-known/oauth-authorization-server
```
Returns aggregated metadata from all configured realms with multi-realm extensions.

### RFC 9728 - Protected Resource Metadata
```
GET /.well-known/oauth-protected-resource/{route}
```
Route-specific resource metadata with audience binding information.

### RFC 8707 - Resource Indicators
- `resource` parameter in authorization requests
- Audience validation in access tokens
- Resource-specific token issuance

## Module Structure

```
src/
├── index.mjs                 # Public API wrapper with validation
├── task/
│   ├── OAuthMiddleware.mjs   # Core middleware implementation
│   ├── server.mjs            # Production server example
│   └── Validation.mjs        # Input validation logic
└── helpers/
    ├── KeycloakClient.mjs    # Keycloak integration
    ├── TokenValidator.mjs    # JWT validation
    ├── OAuthFlowHandler.mjs  # Authorization flow handling
    ├── PKCEGenerator.mjs     # PKCE challenge/verifier
    └── DynamicClientRegistration.mjs # RFC 7591 client registration
```

### Core Components

#### OAuthMiddleware (index.mjs)
- Public API surface
- Input validation via Validation class
- Delegates to implementation

#### OAuthMiddlewareImpl (task/OAuthMiddleware.mjs)
- Express router creation
- Route-to-realm mapping
- Discovery endpoint generation
- Request protection middleware

#### KeycloakClient (helpers/KeycloakClient.mjs)
- Keycloak API integration
- JWKS fetching and caching
- Token introspection
- Multi-realm JWKS aggregation

#### TokenValidator (helpers/TokenValidator.mjs)
- JWT signature verification
- Claims validation
- Scope checking
- Audience binding

#### OAuthFlowHandler (helpers/OAuthFlowHandler.mjs)
- Authorization code flow with PKCE
- Callback handling
- Token exchange
- Error responses

## Security Implementation

### PKCE (Proof Key for Code Exchange)
```javascript
// Automatic generation for each authorization
const { verifier, challenge } = PKCEGenerator.generateCodeVerifier()
const { challengeHash } = PKCEGenerator.generateChallenge(verifier)
```
- S256 method only (SHA256)
- 128-character verifier
- Base64url encoding

### Bearer Token Validation
```javascript
// Strict format enforcement
Authorization: Bearer <token>  // ✅ Valid
?token=<token>                 // ❌ Rejected (OAuth 2.1)
```

### HTTPS Enforcement
```javascript
// Production mode
if (process.env.NODE_ENV === 'production') {
    requireHTTPS() // Enforced
}
// Development mode
if (host === 'localhost' || host === '127.0.0.1') {
    // HTTPS bypassed for local development
}
```

## Request Flow

### 1. Initial Request
```
GET /api/data
→ No token → 401 Unauthorized
→ WWW-Authenticate: Bearer realm="api-realm"
```

### 2. Authorization Flow
```
GET /api/auth/login
→ Generate PKCE challenge
→ Redirect to Keycloak authorization endpoint
```

### 3. Callback Processing
```
GET /api/auth/callback?code=xxx&state=yyy
→ Validate state
→ Exchange code for token (with PKCE verifier)
→ Return access token
```

### 4. Protected Access
```
GET /api/data
Authorization: Bearer <token>
→ Validate JWT signature
→ Check scopes
→ Verify audience
→ Allow access
```

## Multi-Realm Configuration

Each realm configuration requires:

| Field | Type | Purpose | Validation |
|-------|------|---------|------------|
| `keycloakUrl` | string | Keycloak base URL | Valid URL |
| `realm` | string | Realm name | Non-empty |
| `clientId` | string | OAuth client ID | Non-empty |
| `clientSecret` | string | Client secret | Non-empty |
| `requiredScopes` | string[] | Required scopes | Non-empty array |
| `resourceUri` | string | Resource indicator | Valid URI |

### Route Mapping
```javascript
{
    '/api': realmConfigA,     // api-realm
    '/admin': realmConfigB,   // admin-realm
    '/public': realmConfigC   // public-realm
}
```

## Performance Characteristics

- **JWKS Caching**: Keys cached per realm (5 min TTL)
- **Token Validation**: ~1-2ms per request
- **Memory Usage**: ~0.13MB per middleware instance
- **Startup Time**: <100ms for 3 realms

## Error Handling

### OAuth Errors (RFC 6749)
- `invalid_request` - Malformed request
- `invalid_client` - Client authentication failed
- `invalid_grant` - Invalid authorization code
- `unauthorized_client` - Client not authorized
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Requested scope invalid

### HTTP Status Codes
- `401 Unauthorized` - Missing/invalid token
- `403 Forbidden` - Insufficient scopes
- `400 Bad Request` - Malformed request
- `500 Internal Server Error` - Server error

## Testing Coverage

- **Unit Tests**: 73 tests covering all components
- **Integration Tests**: Multi-realm scenarios
- **Performance Tests**: Latency and memory benchmarks
- **RFC Compliance**: Validation against specifications

## Dependencies

- `express` - HTTP server framework
- `jsonwebtoken` - JWT validation
- `jwks-client` - JWKS fetching
- `node-fetch` - HTTP client

## Version Compatibility

- **Node.js**: >=22.0.0 (ES modules)
- **Keycloak**: 20+ (OAuth 2.1 support)
- **Express**: 4.x
- **MCP**: HTTP+SSE transport only