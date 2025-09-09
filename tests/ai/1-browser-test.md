# Complete OAuth 2.1 Flow Browser Test Instructions

This document provides AI assistants with step-by-step instructions for testing the complete OAuth 2.1 authentication flow using Playwright MCP tools.

## Prerequisites

1. **Server Running**: Ensure the OAuth middleware server is running on `http://localhost:3000`
2. **Auth0 Configuration**: Verify Auth0 applications are configured with correct callback URLs
3. **Browser Tools**: Have Playwright MCP browser tools available

## Test Scenario Overview

The complete OAuth flow follows these 8 steps:
1. **Unauthenticated Route Access** - User tries to access protected route
2. **401 Authentication Challenge** - Server responds with WWW-Authenticate header
3. **Well-Known Discovery** - Client follows header to discover OAuth endpoints
4. **OAuth Authorization** - Client redirects to OAuth provider (Auth0)
5. **User Authentication** - User provides credentials on Auth0 login page
6. **Application Consent** - User grants permissions to the application
7. **Callback Handling** - Auth0 redirects back with authorization code
8. **Authenticated Access** - User can now access the originally requested route

---

## Step-by-Step Test Instructions

### Step 1: Access Protected Route (Unauthenticated)

**Goal**: Trigger the OAuth challenge by accessing a protected route without authentication.

```javascript
// Navigate to protected route
mcp__MCP_playwright__browser_navigate({
    url: "http://localhost:3000/first-route/sse"
})

// Take screenshot to document the error
mcp__MCP_playwright__browser_take_screenshot({
    filename: "step1-protected-route-access.png"
})

// Check network requests for 401 response
mcp__MCP_playwright__browser_network_requests()
```

**Expected Result**: 
- HTTP 401 Unauthorized response
- WWW-Authenticate header with Bearer realm and error_description
- Header should contain: `Bearer realm="first-route-realm", error="invalid_token", error_description="Authorization required"`

### Step 2: Verify Authentication Challenge Headers

**Goal**: Confirm the server provides proper OAuth discovery information in headers.

```javascript
// Examine the response headers from previous request
// Look for:
// - Status: 401 Unauthorized
// - WWW-Authenticate: Bearer realm="first-route-realm", error="invalid_token", error_description="Authorization required"
// - Link header (optional): </first-route/discovery>; rel="authorization_server"
```

**Expected Headers**:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="first-route-realm", error="invalid_token", error_description="Authorization required"
Content-Type: application/json
```

### Step 3: Follow Well-Known Discovery Endpoint

**Goal**: Retrieve OAuth server metadata from the well-known endpoint.

```javascript
// Navigate to the well-known protected resource endpoint
mcp__MCP_playwright__browser_navigate({
    url: "http://localhost:3000/.well-known/oauth-protected-resource/first-route"
})

// Take screenshot of the discovery response
mcp__MCP_playwright__browser_take_screenshot({
    filename: "step3-well-known-discovery.png"
})
```

**Expected Response**: JSON document containing:
```json
{
  "resource": "http://localhost:3000/first-route",
  "authorization_servers": ["https://a6b8.eu.auth0.com"],
  "bearer_methods": ["header"],
  "resource_documentation": "http://localhost:3000/first-route/discovery"
}
```

### Step 4: Navigate to OAuth Authorization Endpoint

**Goal**: Start the OAuth authorization flow by visiting the Auth0 authorization endpoint.

```javascript
// Navigate to the OAuth login endpoint
mcp__MCP_playwright__browser_navigate({
    url: "http://localhost:3000/first-route/auth/login"
})

// Wait for Auth0 redirect
mcp__MCP_playwright__browser_wait_for({
    text: "Sign In"
})

// Take screenshot of Auth0 login page
mcp__MCP_playwright__browser_take_screenshot({
    filename: "step4-auth0-login-page.png"
})
```

**Expected Result**:
- Automatic redirect to `https://a6b8.eu.auth0.com/authorize`
- URL contains OAuth parameters:
  - `response_type=code`
  - `client_id=NEMYzVyjtkLOCseuwybCC4HNMPB8I2w6`
  - `redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Ffirst-route%2Fcallback`
  - `scope=openid+profile+email`
  - `code_challenge` and `code_challenge_method=S256` (PKCE)
  - `state` parameter for CSRF protection

### Step 5: Authenticate with Auth0

**Goal**: Complete user authentication on the Auth0 login page.

```javascript
// Take snapshot to see available login options
mcp__MCP_playwright__browser_snapshot()

// If login form is present, fill it out
// Note: This step requires actual Auth0 test credentials
// For demo purposes, document the expected flow

// Expected elements on Auth0 login page:
// - Email/username input field
// - Password input field  
// - "Continue" or "Log In" button
// - Alternative: Social login options (Google, GitHub, etc.)

// Take screenshot before attempting login
mcp__MCP_playwright__browser_take_screenshot({
    filename: "step5-before-auth0-login.png"
})
```

**Note**: For automated testing, you'll need:
- Test Auth0 account credentials
- Or use Auth0's test mode/mock responses
- Or configure Auth0 for headless authentication

### Step 6: Grant Application Permissions (Consent)

**Goal**: Handle the OAuth consent screen where user grants permissions to the application.

```javascript
// Wait for consent screen (if configured in Auth0)
mcp__MCP_playwright__browser_wait_for({
    text: "Allow"
})

// Take screenshot of consent screen
mcp__MCP_playwright__browser_take_screenshot({
    filename: "step6-oauth-consent-screen.png"
})

// Click "Allow" or "Authorize" button
// Note: Auth0 might skip this step for first-party applications
// or if consent was previously granted
```

**Expected Elements**:
- Application name and logo
- List of requested permissions (scopes):
  - "Access your basic profile information"  
  - "Access your email address"
- "Allow" and "Cancel" buttons

### Step 7: Verify Callback Redirect

**Goal**: Confirm successful OAuth callback with authorization code.

```javascript
// Wait for redirect to callback URL
mcp__MCP_playwright__browser_wait_for({
    time: 5
})

// Check final URL after OAuth flow
// Should be back at localhost with callback endpoint
// URL should contain authorization code

// Take screenshot of callback response
mcp__MCP_playwright__browser_take_screenshot({
    filename: "step7-oauth-callback.png"
})

// Check network requests for token exchange
mcp__MCP_playwright__browser_network_requests()
```

**Expected Result**:
- Redirect to: `http://localhost:3000/first-route/callback?code=...&state=...`
- Authorization code in URL parameters
- State parameter matches original request
- Server exchanges code for access token (in background)
- Final redirect to success page or original resource

### Step 8: Access Originally Requested Route

**Goal**: Verify that the user can now access the protected route with valid authentication.

```javascript
// Navigate back to the originally requested protected route
mcp__MCP_playwright__browser_navigate({
    url: "http://localhost:3000/first-route/sse"
})

// Take screenshot of successful access
mcp__MCP_playwright__browser_take_screenshot({
    filename: "step8-successful-authenticated-access.png"
})

// Verify no 401 errors in network requests
mcp__MCP_playwright__browser_network_requests()
```

**Expected Result**:
- HTTP 200 OK response
- Access to the protected MCP server endpoint
- Bearer token automatically included in Authorization header
- Server-sent events stream established (for SSE protocol)

---

## Complete Test Script Template

```javascript
// Complete OAuth 2.1 Flow Test
async function testCompleteOAuthFlow() {
    
    // Step 1: Unauthenticated access
    await mcp__MCP_playwright__browser_navigate({
        url: "http://localhost:3000/first-route/sse"
    })
    
    // Step 2: Check for 401 and WWW-Authenticate header
    const networkRequests = await mcp__MCP_playwright__browser_network_requests()
    // Verify 401 status and authentication challenge
    
    // Step 3: Discover OAuth endpoints
    await mcp__MCP_playwright__browser_navigate({
        url: "http://localhost:3000/.well-known/oauth-protected-resource/first-route"
    })
    
    // Step 4: Start OAuth flow
    await mcp__MCP_playwright__browser_navigate({
        url: "http://localhost:3000/first-route/auth/login"
    })
    
    // Step 5: Auth0 Authentication
    await mcp__MCP_playwright__browser_wait_for({
        text: "Sign In"
    })
    // Handle login form if needed
    
    // Step 6: Consent (if required)
    // Handle consent screen if present
    
    // Step 7: Callback handling
    await mcp__MCP_playwright__browser_wait_for({
        time: 5
    })
    
    // Step 8: Verify authenticated access
    await mcp__MCP_playwright__browser_navigate({
        url: "http://localhost:3000/first-route/sse"
    })
    
    console.log("✅ Complete OAuth 2.1 flow test completed successfully!")
}
```

## Troubleshooting Common Issues

### Issue 1: Auth0 Callback URL Mismatch
**Error**: "Callback URL mismatch. The provided redirect_uri is not in the list of allowed callback URLs"

**Solution**: 
1. Go to Auth0 Dashboard → Applications → [Your App]
2. Add callback URL: `http://localhost:3000/first-route/auth/callback`
3. Add web origins: `http://localhost:3000`

### Issue 2: CORS Errors
**Error**: Cross-origin request blocked

**Solution**: Ensure Auth0 web origins include your localhost domain

### Issue 3: Invalid State Parameter
**Error**: State parameter mismatch

**Solution**: This indicates a potential CSRF attack or session issue. Restart the OAuth flow.

### Issue 4: Token Validation Failures
**Error**: Invalid or expired token

**Solution**: 
1. Check Auth0 token expiration settings
2. Verify JWKS endpoint accessibility
3. Confirm token audience matches resource URI

## Success Criteria

The test is successful when:

✅ **Step 1**: 401 response with proper WWW-Authenticate header  
✅ **Step 2**: Authentication challenge contains realm and error description  
✅ **Step 3**: Well-known endpoint returns valid OAuth metadata  
✅ **Step 4**: Redirect to Auth0 with proper OAuth parameters including PKCE  
✅ **Step 5**: Auth0 login page loads without errors  
✅ **Step 6**: Consent flow completes (if required)  
✅ **Step 7**: Callback succeeds with authorization code  
✅ **Step 8**: Original protected resource is accessible with authentication  

## Notes for AI Assistants

- **Screenshots**: Take screenshots at each major step for debugging
- **Network Monitoring**: Always check network requests for proper HTTP status codes
- **Error Handling**: Document any deviations from expected flow
- **Security Verification**: Confirm PKCE, state parameters, and HTTPS usage
- **Multi-Route Testing**: Repeat test for `/second-route` to verify route-specific configuration

This comprehensive test validates the complete OAuth 2.1 security profile implementation with PKCE, proper error handling, and RFC compliance.