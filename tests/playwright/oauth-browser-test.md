# OAuth 2.1 Browser Test with MCP Inspector

This test validates the complete OAuth 2.1 Authorization Code Flow with PKCE using the MCP Inspector.

## Prerequisites

1. **Auth0 Configuration** - Valid Auth0 application with proper callback URLs
2. **Environment Variables** - `.auth.env` file with correct credentials

## Pre-Test Setup Checklist

### 1. Stop Running Processes
```bash
# Check for running Node.js processes
ps aux | grep -E "(node|npm)" | grep -v grep

# Kill any conflicting processes
kill <PID>
```

### 2. Start Required Services
```bash
# Start MCP Inspector (runs on port 6274)
npm run inspector

# Start FlowMCP Server with OAuth middleware (runs on port 3000) 
npm run start:flowmcp
```

### 3. Verify Auth0 Configuration
Ensure the following callback URLs are configured in Auth0:
- `http://localhost:3000/first-route/auth/callback`
- `http://localhost:6274/oauth/callback/debug` ⚠️ **Critical for Inspector**

## Test Steps

### Step 1: Open Inspector
- Navigate to `http://localhost:6274`
- Verify URL field shows: `http://localhost:3000/first-route`
- Transport Type should be: `SSE`

### Step 2: Start OAuth Flow
1. Click **"Open Auth Settings"** button
2. Click **"Continue"** to begin OAuth discovery

### Step 3: Verify OAuth Discovery Steps
Monitor these steps for green checkmarks ✅:

1. **Metadata Discovery** 
   - ✅ Should succeed (CORS headers required)
   - Tests: `http://localhost:3000/.well-known/oauth-protected-resource/first-route`
   - Validates: Client ID `Uc7Hz7kWlJJkZjHQYweMMsY2OtVi0tR7`

2. **Client Registration**
   - ✅ Should succeed automatically 
   - Uses discovered metadata for OAuth configuration

3. **Preparing Authorization**
   - ✅ Should generate authorization URL with correct parameters
   - Verify Client ID in URL matches server configuration
   - Click **"Open authorization URL in new tab"**

### Step 4: Auth0 Authentication
1. **New tab opens** with Auth0 authorization URL
2. **If successful**: Auth0 login page appears
3. **If error**: Check error details by clicking "See details for this error"
   - Common errors: `Unknown client: <CLIENT_ID>` (wrong client ID in Auth0)
   - Fix: Verify client ID matches in both Auth0 and server config

4. **Complete authentication** at Auth0
5. **Redirected back** to Inspector with authorization code

### Step 5: Complete Token Exchange
1. Inspector should automatically extract the authorization code
2. **Token Request** step should complete ✅
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

### Issue 2: Client ID Mismatch  
**Error**: `Unknown client: <CLIENT_ID>`
**Solution**: Verify client ID consistency:
- Server config: `Uc7Hz7kWlJJkZjHQYweMMsY2OtVi0tR7`
- Auth0 application: Must match exactly
- Inspector discovery: Should auto-detect from server

### Issue 3: Callback URL Mismatch
**Error**: Auth0 redirect fails
**Solution**: Add Inspector callback URL to Auth0:
- `http://localhost:6274/oauth/callback/debug`

### Issue 4: Metadata Discovery Fails
**Error**: `Failed to discover OAuth metadata`
**Solution**: Check if server is running and endpoints are accessible:
```bash
curl http://localhost:3000/.well-known/oauth-protected-resource/first-route
```

## Expected Success Flow

1. ✅ Metadata Discovery
2. ✅ Client Registration  
3. ✅ Preparing Authorization
4. ✅ Request Authorization (Auth0 redirect)
5. ✅ Token Request (code exchange)
6. ✅ Authentication Complete

## Validation Points

- [ ] All 6 steps show green checkmarks
- [ ] Authorization URL contains correct client ID
- [ ] Auth0 login page loads without errors
- [ ] Successful redirect back to Inspector
- [ ] Access token is obtained
- [ ] Can connect to MCP server with OAuth

## Environment Files

Ensure `.auth.env` contains:
```
FIRST_ROUTE_AUTH0_DOMAIN=auth.flowmcp.org
FIRST_ROUTE_AUTH0_CLIENT_ID=Uc7Hz7kWlJJkZjHQYweMMsY2OtVi0tR7
FIRST_ROUTE_AUTH0_CLIENT_SECRET=<secret>
```

## Testing Notes

This test validates the complete OAuth 2.1 implementation including:
- RFC 8414 OAuth Authorization Server Metadata discovery
- RFC 9728 OAuth Protected Resource Metadata discovery  
- RFC 7636 PKCE (Proof Key for Code Exchange)
- RFC 8707 Resource Indicators
- Auth0 custom domain support
- MCP Inspector OAuth integration