# Auth0 Setup Guide

This guide explains how to configure Auth0 for use with the MCP OAuth Middleware package.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Custom Domain Setup](#custom-domain-setup)
- [Application Configuration](#application-configuration)
- [Environment Configuration](#environment-configuration)
- [Discovery Endpoints](#discovery-endpoints)
- [Troubleshooting](#troubleshooting)

## Overview

The MCP OAuth Middleware integrates with Auth0 to provide OAuth 2.1 authentication for Model Context Protocol (MCP) servers. This package supports:

- **Multi-tenant Auth0 setup** with custom domains
- **OAuth 2.1 with PKCE** for enhanced security
- **Automatic Discovery Endpoints** (RFC 8414 & RFC 9728)
- **Multiple application types** (SPA, Regular Web App, Machine to Machine)

## Prerequisites

1. **Auth0 Account** - Sign up at [auth0.com](https://auth0.com)
2. **Custom Domain** (optional but recommended)
3. **DNS Access** - For custom domain verification
4. **Node.js 22+** - For running the middleware

## Custom Domain Setup

### Why Use Custom Domains?

Custom domains provide:
- **Professional appearance** (`auth.yourdomain.com` instead of `yourapp.auth0.com`)
- **Better security** - Your users see your domain
- **SSL certificate management** - Auth0 handles certificates automatically

### Step 1: Configure DNS

1. **Go to Auth0 Dashboard** → Branding → Custom Domains
2. **Add your domain** (e.g., `auth.yourdomain.com`)
3. **Add CNAME record** to your DNS provider:

```dns
Type: CNAME
Name: auth
Value: yourapp.auth0.com
TTL: 300 (or your provider's default)
```

### Step 2: Verify Domain

1. **Wait for DNS propagation** (5-15 minutes)
2. **Click "Verify"** in Auth0 dashboard
3. **Wait for SSL certificate** generation (1-15 minutes)

**Note**: DNS verification can take time. If you see "verification record not found", wait and try again.

### Step 3: Enable Custom Domain

Once verified, your custom domain will be automatically used for **all applications** in your tenant.

## Application Configuration

### Application Types

Choose the appropriate type based on your use case:

| Type | Use Case | PKCE | Client Secret |
|------|----------|------|---------------|
| **Single Page Application (SPA)** | Frontend apps, browser-based | Required | No |
| **Regular Web Application** | Server-side apps | Optional | Yes |
| **Machine to Machine** | API access, server-to-server | No | Yes |

### Creating an Application

1. **Go to Auth0 Dashboard** → Applications
2. **Click "Create Application"**
3. **Choose application type** and fill details

### SPA Configuration

**Best for**: Frontend applications, MCP Inspector

```
Application Type: Single Page Application
Name: Your App Name

Allowed Callback URLs:
https://yourapp.com/callback
http://localhost:3000/callback

Allowed Logout URLs:
https://yourapp.com
http://localhost:3000

Allowed Web Origins:
https://yourapp.com
http://localhost:3000

Allowed Origins (CORS):
https://yourapp.com
http://localhost:3000
```

### Regular Web App Configuration

**Best for**: Server-side applications with backend

```
Application Type: Regular Web Application
Name: Your App Name

Allowed Callback URLs:
https://yourapp.com/callback
http://localhost:3000/callback

Allowed Logout URLs:
https://yourapp.com
http://localhost:3000

Token Endpoint Authentication Method: Post
```

### Machine to Machine Configuration

**Best for**: API access, automated systems

```
Application Type: Machine to Machine
Name: Your API Client

APIs: Select your API
Scopes: Select required scopes (e.g., read:data, write:data)
```

### Advanced Settings

**For all application types:**

```
OAuth 2.0/OIDC Compliance: OIDC Conformant
PKCE: Enabled (for SPA/Web Apps)
Refresh Token Rotation: Enabled
Refresh Token Expiration: Absolute (30 days)
```

## Environment Configuration

### Required Environment Variables

Create a `.env` file or set environment variables:

```env
# Auth0 Configuration (Single Application)
FIRST_ROUTE_AUTH0_DOMAIN=your-custom-domain.com
# OR: FIRST_ROUTE_AUTH0_DOMAIN=yourapp.auth0.com
FIRST_ROUTE_AUTH0_CLIENT_ID=your_client_id_here
FIRST_ROUTE_AUTH0_CLIENT_SECRET=your_client_secret_here

# Static Bearer Token (alternative to OAuth)
THIRD_ROUTE_BEARER_TOKEN=your_static_bearer_token
```

### Middleware Configuration

```javascript
const routeConfigs = [
    {
        routePath: '/api/v1',
        auth: {
            enabled: true,
            providerUrl: 'https://auth.yourdomain.com',
            clientId: process.env.FIRST_ROUTE_AUTH0_CLIENT_ID,
            clientSecret: process.env.FIRST_ROUTE_AUTH0_CLIENT_SECRET,
            scope: 'openid profile email',
            audience: 'https://yourapp.com/api/v1'
        },
        authType: 'oauth'
    }
]
```

### Configuration Parameters

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| `providerUrl` | Auth0 domain (with or without custom domain) | Yes | `https://auth.yourdomain.com` |
| `clientId` | Application Client ID from Auth0 | Yes | `abc123xyz789` |
| `clientSecret` | Application Client Secret (for Web/M2M apps) | No* | `secret_value_here` |
| `scope` | OAuth scopes | No | `openid profile email` |
| `audience` | API identifier/audience | No | `https://yourapp.com/api` |

**\*Note**: Client Secret required for Regular Web Apps and Machine to Machine

## Discovery Endpoints

The middleware automatically generates OAuth Discovery endpoints:

### Authorization Server Metadata (RFC 8414)

```
GET /your-route/.well-known/oauth-authorization-server
```

**Response:**
```json
{
    "issuer": "https://auth.yourdomain.com",
    "authorization_endpoint": "https://auth.yourdomain.com/authorize",
    "token_endpoint": "https://auth.yourdomain.com/oauth/token",
    "userinfo_endpoint": "https://auth.yourdomain.com/userinfo",
    "jwks_uri": "https://auth.yourdomain.com/.well-known/jwks.json",
    "scopes_supported": ["openid", "profile", "email"],
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "client_credentials"],
    "code_challenge_methods_supported": ["S256"]
}
```

### Protected Resource Metadata (RFC 9728)

```
GET /your-route/.well-known/oauth-protected-resource
```

**Response:**
```json
{
    "resource": "https://yourapp.com/your-route",
    "authorization_servers": ["https://auth.yourdomain.com"],
    "scopes_supported": ["openid", "profile", "email"],
    "bearer_methods_supported": ["header"]
}
```

## Troubleshooting

### Common Issues

#### 1. Custom Domain Not Working

**Symptoms:**
- Domain shows as verified but not working
- SSL certificate errors

**Solutions:**
- Wait 15-30 minutes for SSL certificate generation
- Check DNS propagation: `dig auth.yourdomain.com`
- Verify CNAME points to correct Auth0 domain

#### 2. CORS Errors

**Symptoms:**
- Browser blocks OAuth requests
- "Access to fetch blocked by CORS policy"

**Solutions:**
- Add your domain to "Allowed Origins (CORS)" in Auth0 app settings
- Include `http://localhost:3000` for development
- Ensure protocol matches (http vs https)

#### 3. Invalid Client/Callback URL

**Symptoms:**
- "callback URL mismatch" errors
- Authentication flow fails

**Solutions:**
- Verify callback URLs in Auth0 app settings
- Include both production and development URLs
- Check for trailing slashes consistency

#### 4. Token Validation Failures

**Symptoms:**
- "Invalid token" errors
- 401 Unauthorized responses

**Solutions:**
- Verify `audience` parameter matches API identifier
- Check token expiration
- Ensure scopes are correctly configured

### Debug Mode

Enable debug logging:

```javascript
const middleware = await McpAuthMiddleware.create({
    routes: routeConfigs,
    silent: false  // Enable logging
})
```

### Testing Your Setup

1. **Test Discovery Endpoints:**
```bash
curl https://yourapp.com/your-route/.well-known/oauth-authorization-server
```

2. **Test Authentication Flow:**
- Open your application in browser
- Trigger OAuth login
- Check browser network tab for request/response details

3. **Verify Token:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" https://yourapp.com/your-route
```

### Get Help

- **Auth0 Community**: [community.auth0.com](https://community.auth0.com)
- **Auth0 Documentation**: [auth0.com/docs](https://auth0.com/docs)
- **Package Issues**: [GitHub Issues](https://github.com/flowmcp/oauth-middleware/issues)

---

## Next Steps

1. **Set up your custom domain** following the DNS configuration
2. **Create your application** in Auth0 dashboard
3. **Configure environment variables** for your routes
4. **Test the OAuth flow** with your application
5. **Review security settings** and enable production features

For more examples, see the `tests/manual/` directory in this package.