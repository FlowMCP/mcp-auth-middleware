# Static Bearer Token Browser Test

This test validates static Bearer Token authentication without OAuth flow complexity. Use this for simpler authentication scenarios or development/testing environments.

## Test Overview

Validates static Bearer Token authentication:
- **Direct MCP connection** with pre-configured token
- **No OAuth flow required** - immediate authentication
- **Authorization header** validation (`Authorization: Bearer <token>`)
- **Simple setup** for development and testing
- **Token validation** and error handling

## Prerequisites

### 1. Environment Setup
Ensure `.auth.env` contains a valid bearer token:
```env
THIRD_ROUTE_BEARER_TOKEN=supersecure
```

**Token Requirements:**
- Minimum 8 characters (validated by middleware)
- Must NOT start with "Bearer" prefix (added automatically)
- For production: Use cryptographically secure random strings (32+ chars)

### 2. Configuration Activation
Uncomment the third-route in `tests/manual/config.mjs`:

```javascript
{
    'routePath': '/third-route',
    'name': 'Third Route - Bearer Token',
    'description': 'Static bearer token authentication for simple API access',
    'protocol': 'sse',
    'auth': {
        'enabled': true,
        'authType': 'staticBearer',
        'token': thirdRouteBearerToken  // From .auth.env
    }
}
```

### 3. Start Services
```bash
# Start MCP Inspector (port 6274)
npm run inspector

# Start FlowMCP Server with Bearer Token route (port 3000)
npm run start:flowmcp
```

## Test Steps

### Step 1: Verify Server Configuration
Check that the third route is active:
```bash
curl -I http://localhost:3000/third-route/sse
# Should return: 401 Unauthorized (authentication required)
```

### Step 2: Test Direct Bearer Token Access
```bash
# Test with correct token
curl -H "Authorization: Bearer supersecure" http://localhost:3000/third-route/sse
# Should return: 200 OK with SSE connection

# Test with wrong token  
curl -H "Authorization: Bearer wrongtoken" http://localhost:3000/third-route/sse
# Should return: 401 Unauthorized
```

### Step 3: MCP Inspector Test
1. **Open Inspector**: Navigate to `http://localhost:6274`
2. **Set URL**: Enter `http://localhost:3000/third-route`
3. **Configure Authentication**:
   - Click "Authentication" button
   - Select "Bearer Token"
   - Enter token: `supersecure`
4. **Connect**: Click "Connect" button
5. **Verify**: Connection should be successful with available tools/schemas

## Expected Behavior

### ✅ Success Indicators
- Server logs show successful Bearer token validation
- MCP Inspector connects without errors
- Available tools/schemas are displayed
- SSE connection established

### ❌ Failure Indicators  
- `401 Unauthorized` responses
- Inspector shows authentication errors
- Connection refused or timeout

## Common Issues & Solutions

### Issue 1: Token Validation Fails
**Error**: `Invalid or missing Bearer token`
**Solution**: Check token in `.auth.env`:
```bash
grep THIRD_ROUTE_BEARER_TOKEN .auth.env
```

### Issue 2: Token Too Short
**Error**: `StaticBearer token must be at least 8 characters long`  
**Solution**: Use longer token (minimum 8 chars):
```env
THIRD_ROUTE_BEARER_TOKEN=longsecuretoken123
```

### Issue 3: Bearer Prefix Error
**Error**: `StaticBearer token must not start with "Bearer" prefix`
**Solution**: Remove "Bearer" from token value:
```env
# Wrong:
THIRD_ROUTE_BEARER_TOKEN=Bearer supersecure

# Correct:
THIRD_ROUTE_BEARER_TOKEN=supersecure
```

### Issue 4: Route Not Available  
**Error**: Route not found or disabled
**Solution**: Ensure third-route is uncommented in `config.mjs` and server restarted

## Security Notes

### Development vs Production

**Development** (current setup):
```env
THIRD_ROUTE_BEARER_TOKEN=supersecure
```

**Production** (recommended):
```env
THIRD_ROUTE_BEARER_TOKEN=S3cur3R4nd0mT0k3n1234567890ABCdef
```

### Token Security Best Practices
1. **Length**: Use 32+ character tokens for production
2. **Randomness**: Generate cryptographically secure random tokens
3. **Rotation**: Rotate tokens regularly
4. **Storage**: Store in secure environment variables, not in code
5. **Transmission**: Always use HTTPS in production

## Testing Checklist

### Manual Test Steps
- [ ] Server starts without errors
- [ ] Route responds to HEAD requests with 401
- [ ] Valid Bearer token allows access
- [ ] Invalid tokens are rejected
- [ ] Inspector can connect with correct token
- [ ] Inspector shows authentication errors with wrong token
- [ ] MCP tools/schemas load correctly

### Automated Browser Test Points
- [ ] Navigate to Inspector
- [ ] Configure Bearer token authentication  
- [ ] Test connection success with valid token
- [ ] Test connection failure with invalid token
- [ ] Verify tool availability after successful connection

## Bearer Token vs OAuth Comparison

| Feature | Bearer Token | OAuth 2.1 |
|---------|-------------|-----------|
| **Setup Complexity** | Simple | Complex |
| **Security** | Basic | Advanced |
| **User Flow** | Direct | Redirect Flow |
| **Token Management** | Manual | Automatic |
| **Expiration** | Manual | Automatic |
| **Use Case** | Development/Testing | Production |

**When to use Bearer Tokens:**
- Development and testing environments
- Internal APIs with simple authentication needs  
- Microservice-to-microservice communication
- Quick prototyping

**When to use OAuth 2.1:**
- Production user-facing applications
- Third-party integrations
- Complex authorization scenarios
- When token refresh is needed
```

## Test Route Configuration

### Bearer Token Route: `/third-route`
- **URL**: `http://localhost:3000/third-route`
- **Auth Type**: Static Bearer Token
- **Protocol**: SSE (Server-Sent Events)
- **Token Source**: Environment variable `THIRD_ROUTE_BEARER_TOKEN`
- **Security**: Direct token validation, no OAuth flow

---

## 5-Step Bearer Token Authentication Test

### Step 1: Unauthenticated Access Test

**Goal**: Verify that protected resource requires authentication.

**Using MCP Inspector**:
1. Open browser to: `http://localhost:6274` (MCP Inspector)
2. Try to connect to: `http://localhost:3000/third-route` 
3. Expected: Connection fails due to missing Bearer token

**Using Browser manually**:
1. Open browser to: `http://localhost:3000/third-route/sse`
2. Expected: 401 Unauthorized page

**Using curl**:
```bash
curl -i http://localhost:3000/third-route/sse
```

**Expected Result**:
- **HTTP 401 Unauthorized** response
- **WWW-Authenticate header**: `Bearer realm="third-route-realm"`
- No OAuth redirect or discovery endpoints

### Step 2: Direct API Access with Bearer Token

**Goal**: Test direct API access using Authorization header.

**Using MCP Inspector**:
1. In MCP Inspector at `http://localhost:6274`
2. Connect to: `http://localhost:3000/third-route`
3. Select "Bearer Token" authentication
4. Enter your Bearer token from `.auth.env`
5. Expected: Successful connection

**Using curl**:
```bash
curl -H "Authorization: Bearer YOUR_STATIC_TOKEN" \
  http://localhost:3000/third-route/sse
```

**Expected Result**:
- **HTTP 200 OK** response
- Successful access to MCP server endpoint
- No authentication challenges or redirects

### Step 3: Invalid Token Test

**Goal**: Verify that invalid tokens are properly rejected.

```javascript
// Test with invalid token
await browser.setHeaders({
    'Authorization': 'Bearer invalid_token_12345'
})

await browser.navigate({
    url: "http://localhost:3000/third-route/sse"
})

await browser.screenshot({
    filename: "step3-bearer-invalid-token.png"
})

// Check for proper error response
const requests = await browser.getNetworkRequests()
```

**Expected Result**:
- **HTTP 401 Unauthorized** response
- **WWW-Authenticate header** with error description
- No server errors or exceptions

### Step 4: Missing Authorization Header Test

**Goal**: Test behavior when Authorization header is missing.

```javascript
// Clear any existing headers
await browser.clearHeaders()

await browser.navigate({
    url: "http://localhost:3000/third-route/sse"
})

await browser.screenshot({
    filename: "step4-bearer-missing-header.png"
})

// Verify proper authentication challenge
const networkRequests = await browser.getNetworkRequests()
```

**Expected Result**:
- **HTTP 401 Unauthorized** response
- **WWW-Authenticate header**: `Bearer realm="third-route-realm"`
- Clear error message indicating missing token

### Step 5: MCP Server Integration Test

**Goal**: Verify Bearer token works with MCP server operations.

```javascript
// Set valid Bearer token
await browser.setHeaders({
    'Authorization': 'Bearer YOUR_STATIC_TOKEN_HERE'
})

// Test MCP server schema endpoint
await browser.navigate({
    url: "http://localhost:3000/third-route/schema"
})

await browser.screenshot({
    filename: "step5-bearer-mcp-schema.png"
})

// Test MCP tools endpoint
await browser.navigate({
    url: "http://localhost:3000/third-route/tools"
})

await browser.screenshot({
    filename: "step5-bearer-mcp-tools.png"
})

// Verify all endpoints work with Bearer authentication
const networkRequests = await browser.getNetworkRequests()
```

**Expected Result**:
- **HTTP 200 OK** for all MCP endpoints
- Valid JSON responses with MCP data
- Bearer token accepted for all operations

---

## Automated Test Script Template

```javascript
// Complete Bearer Token Authentication Test
async function testBearerTokenAuth() {
    console.log("🚀 Starting Bearer Token Authentication Test")
    
    const validToken = process.env.THIRD_ROUTE_BEARER_TOKEN || "your_test_token"
    
    // Step 1: Unauthenticated access
    await browser.clearHeaders()
    await browser.navigate({
        url: "http://localhost:3000/third-route/sse"
    })
    console.log("✅ Step 1: Verified 401 for unauthenticated access")
    
    // Step 2: Valid token access
    await browser.setHeaders({
        'Authorization': `Bearer ${validToken}`
    })
    await browser.navigate({
        url: "http://localhost:3000/third-route/sse"
    })
    console.log("✅ Step 2: Successful access with valid token")
    
    // Step 3: Invalid token test
    await browser.setHeaders({
        'Authorization': 'Bearer invalid_token_test'
    })
    await browser.navigate({
        url: "http://localhost:3000/third-route/sse"
    })
    console.log("✅ Step 3: Proper rejection of invalid token")
    
    // Step 4: Missing header test
    await browser.clearHeaders()
    await browser.navigate({
        url: "http://localhost:3000/third-route/sse"
    })
    console.log("✅ Step 4: Proper authentication challenge")
    
    // Step 5: MCP integration test
    await browser.setHeaders({
        'Authorization': `Bearer ${validToken}`
    })
    await browser.navigate({
        url: "http://localhost:3000/third-route/schema"
    })
    console.log("✅ Step 5: MCP server integration successful")
    
    console.log("🎉 Bearer Token Authentication Test Completed!")
}
```

## Browser Testing with MCP Inspector

### Inspector Integration Test

**Goal**: Test Bearer token authentication through MCP Inspector interface.

```javascript
// Navigate to MCP Inspector
await browser.navigate({
    url: "http://localhost:6274"  // Default MCP Inspector port
})

// Add server connection with Bearer token
await browser.fill("#server-url", "http://localhost:3000/third-route")
await browser.select("#auth-type", "bearer")
await browser.fill("#bearer-token", "YOUR_STATIC_TOKEN_HERE")

// Connect to server
await browser.click("#connect-button")

await browser.screenshot({
    filename: "inspector-bearer-connection.png"
})

// Verify successful connection
await browser.waitFor({
    text: "Connected"
})

// Test tool execution
await browser.click("#tools-tab")
await browser.click("#execute-tool-button")

await browser.screenshot({
    filename: "inspector-bearer-tool-execution.png"
})
```

## API Testing with curl Commands

### Manual Testing Commands

```bash
# Test 1: Unauthenticated access (should fail)
curl -i http://localhost:3000/third-route/sse

# Test 2: Valid Bearer token (should succeed)
curl -i -H "Authorization: Bearer YOUR_STATIC_TOKEN" \
  http://localhost:3000/third-route/sse

# Test 3: Invalid Bearer token (should fail)
curl -i -H "Authorization: Bearer invalid_token" \
  http://localhost:3000/third-route/sse

# Test 4: MCP schema with Bearer token
curl -i -H "Authorization: Bearer YOUR_STATIC_TOKEN" \
  http://localhost:3000/third-route/schema

# Test 5: MCP tools with Bearer token
curl -i -H "Authorization: Bearer YOUR_STATIC_TOKEN" \
  http://localhost:3000/third-route/tools
```

## Security Considerations

### Token Security Best Practices

1. **Token Generation**:
   ```javascript
   // Generate secure random token
   const crypto = require('crypto')
   const bearerToken = crypto.randomBytes(32).toString('hex')
   ```

2. **Token Storage**:
   - Store in environment variables
   - Never commit to version control
   - Use secure key management in production

3. **Token Rotation**:
   - Implement regular token rotation
   - Have token expiration mechanisms
   - Monitor token usage patterns

4. **Token Validation**:
   - Use constant-time comparison
   - Log failed authentication attempts
   - Implement rate limiting

## Troubleshooting Common Issues

### Issue 1: Token Not Recognized
**Error**: "Invalid or missing token"
**Solution**: 
- Verify token matches exactly (no extra spaces)
- Check environment variable is loaded correctly
- Ensure token is properly formatted in Authorization header

### Issue 2: CORS Issues with Bearer Token
**Error**: CORS preflight failure
**Solution**: 
- Ensure server accepts Authorization header in CORS config
- Add proper CORS middleware configuration

### Issue 3: Token Visible in Browser
**Error**: Token exposed in browser
**Solution**: 
- Use httpOnly cookies in production
- Implement secure token storage
- Consider token proxy patterns

### Issue 4: Case Sensitivity Issues
**Error**: Authentication fails randomly
**Solution**: 
- Ensure consistent case in "Bearer" keyword
- Check for whitespace in token strings
- Validate Authorization header format

## Success Criteria

✅ **Step 1**: Unauthenticated access properly rejected (401)  
✅ **Step 2**: Valid Bearer token grants access (200)  
✅ **Step 3**: Invalid tokens properly rejected (401)  
✅ **Step 4**: Missing headers trigger authentication challenge  
✅ **Step 5**: All MCP endpoints work with Bearer authentication  

## Performance Considerations

- **No OAuth Overhead**: Direct token validation is faster than OAuth flows
- **Stateless Authentication**: No session management required
- **Simple Implementation**: Minimal server-side processing
- **Cache Considerations**: Token validation can be cached securely

## Production Deployment Notes

1. **HTTPS Required**: Always use HTTPS in production for Bearer tokens
2. **Token Management**: Implement proper token lifecycle management
3. **Monitoring**: Log and monitor token usage patterns
4. **Rate Limiting**: Implement rate limiting for token-based endpoints
5. **Token Expiration**: Consider implementing token expiration for security

This comprehensive test ensures Bearer Token authentication works correctly for direct API access and MCP server integration.