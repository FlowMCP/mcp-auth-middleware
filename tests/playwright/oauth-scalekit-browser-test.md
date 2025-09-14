# OAuth 2.1 ScaleKit Browser Test with MCP Inspector

This test validates the complete OAuth 2.1 Authorization Code Flow with PKCE using ScaleKit as the OAuth provider and the MCP Inspector.

## Prerequisites

1. **ScaleKit Configuration** - Valid ScaleKit application with proper callback URLs
2. **Environment Variables** - `.auth.env` file with correct ScaleKit credentials
3. **MCP Server Implementation** - Running oauth21_scalekit AuthType

## Pre-Test Setup Checklist

### 1. Verify ScaleKit Credentials
Ensure `.auth.env` contains all required ScaleKit credentials:
```env
SCALEKIT_ENVIRONMENT_URL=https://your-domain.scalekit.dev
SCALEKIT_CLIENT_ID=your_client_id_here
SCALEKIT_CLIENT_SECRET=your_client_secret_here
SCALEKIT_MCP_ID=your_mcp_resource_id
```

### 2. Stop Running Processes
```bash
# Check for running Node.js processes
ps aux | grep -E "(node|npm)" | grep -v grep

# Kill any conflicting processes
kill <PID>
```

### 3. Start Required Services
```bash
# Start MCP Inspector (runs on port 6274)
npm run inspector

# Start FlowMCP Server with ScaleKit OAuth middleware (runs on port 3000)
npm run start:flowmcp
```

### 4. Verify ScaleKit Configuration
Ensure the following callback URLs are configured in ScaleKit:
- `http://localhost:3000/scalekit-route/auth/callback`
- `http://localhost:6274/oauth/callback/debug` ⚠️ **Critical for Inspector**

## Test Steps

### Step 1: Open Inspector
- Navigate to `http://localhost:6274`
- Change URL field to: `http://localhost:3000/scalekit-route`
- Transport Type should be: `SSE`

### Step 2: Start OAuth Flow
1. Click **"Open Auth Settings"** button
2. Click **"Continue"** to begin OAuth discovery

### Step 3: Verify OAuth Discovery Steps
Monitor these steps for green checkmarks ✅:

1. **Metadata Discovery**
   - ✅ Should succeed (CORS headers required)
   - Tests: `http://localhost:3000/.well-known/oauth-protected-resource/scalekit-route`
   - Validates: ScaleKit MCP ID (from your configuration)
   - Validates: ScaleKit Provider URL

2. **Client Registration**
   - ✅ Should succeed automatically
   - Uses discovered metadata for OAuth configuration
   - ScaleKit authorization server: `https://your-domain.scalekit.dev/resources/your_mcp_id`

3. **Preparing Authorization**
   - ✅ Should generate authorization URL with correct parameters
   - Verify ScaleKit domain in URL: `your-domain.scalekit.dev`
   - Verify Client ID: `your_client_id_here`
   - Click **"Open authorization URL in new tab"**

### Step 4: ScaleKit Authentication
1. **New tab opens** with ScaleKit authorization URL
2. **If successful**: ScaleKit login page appears with domain branding
3. **If error**: Check error details by clicking "See details for this error"
   - Common errors:
     - `Invalid client_id` (wrong client ID in ScaleKit)
     - `Invalid redirect_uri` (callback URL not configured)
     - `Invalid scope` (MCP scopes not supported)

4. **Complete authentication** at ScaleKit:
   - Enter credentials for your ScaleKit organization
   - Approve MCP scope permissions:
     - `mcp:tools:*`
     - `mcp:resources:read`
     - `mcp:resources:write`

5. **Redirected back** to Inspector with authorization code

### Step 5: Complete Token Exchange
1. Inspector should automatically extract the authorization code
2. **Token Request** step should complete ✅
   - Token endpoint: `https://your-domain.scalekit.dev/oauth/token`
   - PKCE code verifier validation
3. **Authentication Complete** step should show ✅
4. Access token should be available for MCP connection

## Common Issues & Solutions

### Issue 1: CORS Errors
**Error**: `Access to fetch blocked by CORS policy`
**Solution**: Ensure CORS middleware is configured in FlowMCP server:
```javascript
app.use( cors( {
    origin: '*',
    methods: [ 'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS' ],
    allowedHeaders: [ 'Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'mcp-protocol-version' ]
} ) )
```

### Issue 2: ScaleKit Client ID Mismatch
**Error**: `Invalid client_id`
**Solution**: Verify client ID consistency:
- Server config: Use your actual ScaleKit client ID
- ScaleKit application: Must match exactly
- Inspector discovery: Should auto-detect from server

### Issue 3: Callback URL Mismatch
**Error**: ScaleKit redirect fails with `Invalid redirect_uri`
**Solution**: Add Inspector callback URL to ScaleKit application:
- `http://localhost:6274/oauth/callback/debug`
- `http://localhost:3000/scalekit-route/auth/callback`

### Issue 4: Metadata Discovery Fails
**Error**: `Failed to discover OAuth metadata`
**Solution**: Check if server is running and endpoints are accessible:
```bash
# Test protected resource metadata
curl http://localhost:3000/.well-known/oauth-protected-resource/scalekit-route

# Test authorization server metadata
curl http://localhost:3000/.well-known/oauth-authorization-server/scalekit-route
```

### Issue 5: Invalid Scope Error
**Error**: `Invalid scope` or `Unsupported scope`
**Solution**: Ensure ScaleKit application supports MCP scopes:
- Configure custom scopes in ScaleKit: `mcp:tools:*`, `mcp:resources:read`, `mcp:resources:write`
- Or use standard scopes: `openid profile email` (if MCP scopes not supported)

### Issue 6: JWKS Validation Fails
**Error**: Token validation fails after successful authorization
**Solution**: Verify JWKS endpoint accessibility:
```bash
# Test ScaleKit JWKS endpoint
curl https://your-domain.scalekit.dev/keys
```

## Expected Success Flow

1. ✅ Metadata Discovery
2. ✅ Client Registration
3. ✅ Preparing Authorization
4. ✅ Request Authorization (ScaleKit redirect)
5. ✅ Token Request (code exchange)
6. ✅ Authentication Complete

## Validation Points

- [ ] All 6 steps show green checkmarks
- [ ] Authorization URL contains correct ScaleKit domain
- [ ] Authorization URL contains correct client ID
- [ ] ScaleKit login page loads without errors
- [ ] MCP scope permissions are requested
- [ ] Successful redirect back to Inspector
- [ ] Access token is obtained and validated
- [ ] Can connect to MCP server with ScaleKit OAuth

## ScaleKit-Specific Validation

### Token Validation
After successful authentication, verify:
- [ ] Token issuer matches: `https://your-domain.scalekit.dev`
- [ ] Token audience matches: `http://localhost:3000/scalekit-route/sse`
- [ ] Token contains required MCP scopes
- [ ] JWKS-based signature validation works

### Well-Known Metadata
Verify correct ScaleKit metadata generation:
```bash
# Should return ScaleKit-specific metadata
curl http://localhost:3000/.well-known/oauth-protected-resource/scalekit-route
```

Expected response structure:
```json
{
  "authorization_servers": ["https://your-domain.scalekit.dev/resources/res_90153735103187214"],
  "bearer_methods_supported": ["header"],
  "resource": "http://localhost:3000/scalekit-route/sse",
  "resource_documentation": "http://localhost:3000/scalekit-route/docs",
  "scopes_supported": ["mcp:tools:*", "mcp:resources:read", "mcp:resources:write"]
}
```

## Environment Files

Ensure `.auth.env` contains all ScaleKit credentials:
```env
# ScaleKit OAuth Configuration
SCALEKIT_ENVIRONMENT_URL=https://your-domain.scalekit.dev
SCALEKIT_CLIENT_ID=your_client_id_here
SCALEKIT_CLIENT_SECRET=your_client_secret_here
SCALEKIT_MCP_ID=your_mcp_resource_id

# Other routes (can remain for testing)
FIRST_ROUTE_AUTH0_DOMAIN=auth.flowmcp.org
FIRST_ROUTE_AUTH0_CLIENT_ID=Uc7Hz7kWlJJkZjHQYweMMsY2OtVi0tR7
FIRST_ROUTE_AUTH0_CLIENT_SECRET=<secret>
THIRD_ROUTE_BEARER_TOKEN=supersecure
```

## Testing Notes

This test validates the ScaleKit OAuth 2.1 implementation including:
- **RFC 8414** OAuth Authorization Server Metadata discovery
- **RFC 9728** OAuth Protected Resource Metadata discovery
- **RFC 7636** PKCE (Proof Key for Code Exchange)
- **RFC 8707** Resource Indicators
- **ScaleKit MCP Integration** with custom scopes
- **JWKS-based token validation** without client credentials
- **MCP Inspector OAuth integration** with ScaleKit

## Troubleshooting ScaleKit-Specific Issues

### Debug Endpoints
Use these endpoints for troubleshooting:
```bash
# ScaleKit OpenID Discovery
curl https://your-domain.scalekit.dev/.well-known/openid-configuration

# ScaleKit JWKS
curl https://your-domain.scalekit.dev/keys

# Resource metadata
curl http://localhost:3000/.well-known/oauth-protected-resource/scalekit-route

# Authorization server metadata
curl http://localhost:3000/.well-known/oauth-authorization-server/scalekit-route
```

### Common ScaleKit Errors
- **Domain not configured**: Verify `flowmcp-afaeuirdaafqi.scalekit.dev` is correct
- **MCP ID mismatch**: Check `res_90153735103187214` in both config and ScaleKit
- **Client credentials invalid**: Verify `skc_90153504634571524` client ID
- **Callback URL rejected**: Add Inspector URLs to ScaleKit application configuration

## Success Criteria

✅ **Complete OAuth Flow**: All 6 steps complete successfully
✅ **ScaleKit Integration**: Login redirects to correct ScaleKit domain
✅ **MCP Scope Support**: Custom MCP scopes are handled correctly
✅ **Token Validation**: JWKS-based validation works without client secrets
✅ **Inspector Integration**: MCP Inspector connects successfully with ScaleKit OAuth
✅ **Well-Known Metadata**: Correct ScaleKit-specific metadata generation