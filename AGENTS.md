# AI Agent Guide - OAuth MCP Middleware

This guide provides AI agents with essential information for working with the OAuth MCP Middleware codebase.

## Repository Overview

**Purpose**: OAuth 2.1 middleware for securing Model Context Protocol (MCP) server endpoints
**Transport**: HTTP + SSE (Server-Sent Events) only
**Security**: OAuth 2.1 with PKCE, Bearer tokens, HTTPS enforcement
**Architecture**: Express-compatible middleware with AuthType-based authentication

## Key Documentation

### 📖 Technical Documentation
- **[src/MCP_AUTH_MIDDLEWARE.md](./src/MCP_AUTH_MIDDLEWARE.md)** - Complete technical specifications, architecture, RFC compliance, and implementation details
- **[src/AUTH_TYPE.md](./src/AUTH_TYPE.md)** - AuthType system documentation

### 📋 User Documentation  
- **[README.md](./README.md)** - Minimal usage guide with installation, basic configuration, and API reference

## Code Architecture

### Entry Point
- **[src/index.mjs](./src/index.mjs)** - Public API wrapper with input validation
- All imports MUST go through this file only

### Core Implementation
- **[src/task/McpAuthMiddleware.mjs](./src/task/McpAuthMiddleware.mjs)** - Main middleware implementation
- **[src/task/Validation.mjs](./src/task/Validation.mjs)** - Input validation logic

### Helper Modules
- **[src/helpers/](./src/helpers/)** - OAuthFlowHandler, PKCEGenerator, Logger

### Test Suite
- **73 unit tests** with comprehensive coverage
- **AuthType scenarios** in `tests/unit/`
- **RFC compliance tests** for OAuth 2.1, RFC 8414, 9728, 8707

## Important Constraints

### ⚠️ Critical Rules
1. **Single Entry Point**: All imports must go through `src/index.mjs`
2. **AuthType Required**: All routes must specify authType (oauth21_auth0, oauth21_scalekit, or staticBearer)
3. **Validation Required**: All public methods must validate inputs
4. **Transport Limitation**: HTTP+SSE only, no stdio support
5. **OAuth 2.1 Only**: No other authentication methods supported

### 🔒 Security Requirements
- HTTPS enforcement in production
- Bearer tokens only (header-based)
- PKCE mandatory for all flows
- No URL parameter tokens allowed
- Audience binding validation

### 📁 File Structure
```
src/
├── index.mjs                 # Public API (ONLY entry point)
├── task/
│   ├── McpAuthMiddleware.mjs   # Core implementation
│   └── Validation.mjs        # Input validation
└── helpers/
    ├── OAuthFlowHandler.mjs
    └── PKCEGenerator.mjs
```

## Working with This Codebase

### Configuration Pattern
```javascript
const middleware = await McpAuthMiddleware.create({
    routes: {
        '/route': {
            authType: 'oauth21_scalekit', // Auth type identifier
            providerUrl: 'string',     // Provider base URL
            clientId: 'string',
            clientSecret: 'string',
            requiredScopes: ['array'],
            forceHttps: true,          // Route-specific HTTPS enforcement
            resourceUri: 'string'
        }
    }
})
```

### Public API Methods
- `.create({ routes, silent? })` - Create middleware instance
- `.router()` - Get Express router with OAuth endpoints
- `.getRoutes()` - Get configured routes array
- `.getRouteConfig({ routePath })` - Get specific route config

### Testing Commands
```bash
npm test                    # Run all 73 tests
npm run test:coverage:src   # Run with coverage report
```

## OAuth Flow Endpoints (Auto-Generated)
```
/route/auth/login      # Initiate OAuth flow
/route/auth/callback   # OAuth callback handler
```

## Discovery Endpoints (RFC Compliant)
```
/.well-known/oauth-authorization-server         # RFC 8414
/.well-known/jwks.json                         # Aggregated JWKS
/.well-known/oauth-protected-resource/route    # RFC 9728
```

## Common Issues & Solutions

### ❌ Import Errors
- **Problem**: Direct imports from `src/task/` or `src/helpers/`
- **Solution**: Always import from `src/index.mjs`

### ❌ Missing AuthType Configuration
- **Problem**: Routes without authType specification
- **Solution**: Add `authType: 'oauth21_auth0'`, `authType: 'oauth21_scalekit'`, or `authType: 'staticBearer'`

### ❌ Missing Validation
- **Problem**: Calling implementation methods directly
- **Solution**: Use public API methods with built-in validation

### ❌ Transport Confusion  
- **Problem**: Attempting stdio or WebSocket usage
- **Solution**: This middleware is HTTP+SSE only

## Development Workflow

1. **Read Technical Docs**: Start with `src/OAUTH_MCP_MIDDLEWARE.md`
2. **Understand Architecture**: Single entry point through `src/index.mjs`
3. **Check Tests**: Review relevant test files for examples
4. **Validate Changes**: Run test suite before modifications
5. **Maintain Security**: Follow OAuth 2.1 security standards

## Environment Configuration

### New TestUtils API Pattern
Use `TestUtils.getEnvParams()` with selection pattern:

```javascript
const credentials = TestUtils.getEnvParams( {
    'envPath': './../../.auth.env',
    'selection': [
        [ 'AUTH0_DOMAIN', 'AUTH0_DOMAIN' ],
        [ 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_ID' ],
        [ 'AUTH0_CLIENT_SECRET', 'AUTH0_CLIENT_SECRET' ]
    ]
} )
```

- **envPath**: Never hardcoded, always configurable
- **selection**: Array of [outputKey, envKey] mappings

## Key Technologies

- **Node.js 22** with ES modules (.mjs)
- **Express.js** for HTTP server
- **Multi-AuthType Support**: oauth21_auth0, oauth21_scalekit, staticBearer
- **Jest** for testing
- **OAuth 2.1** security profile
- **RFC 8414, 9728, 8707** compliance

## Performance Characteristics

- **Startup**: <100ms for 3 routes
- **Memory**: ~0.13MB per instance  
- **Latency**: ~1-2ms token validation
- **JWKS Caching**: 5 minute TTL per provider

---

**For detailed technical information, see [src/OAUTH_MCP_MIDDLEWARE.md](./src/OAUTH_MCP_MIDDLEWARE.md)**