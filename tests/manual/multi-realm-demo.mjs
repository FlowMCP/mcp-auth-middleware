import express from 'express'
import { OAuthMiddleware } from '../../src/index.mjs'

/**
 * Multi-Realm OAuth Middleware Demo Server
 * 
 * Demonstrates the new multi-realm architecture with multiple protected routes,
 * each mapped to different Keycloak realms with different scope requirements.
 * 
 * Features:
 * - Multi-realm OAuth with route-specific configurations
 * - RFC 8414, 9728, 8707 compliance
 * - OAuth 2.1 security standards
 * - Automatic discovery endpoints
 * - Resource indicator support
 * - PKCE enforcement
 * 
 * Routes:
 * - /api/*     - Protected by 'api-realm', requires ['api:read', 'api:write']
 * - /admin/*   - Protected by 'admin-realm', requires ['admin:full']
 * - /public/*  - Protected by 'public-realm', requires ['user:basic']
 * 
 * Discovery Endpoints (automatically generated):
 * - /.well-known/oauth-authorization-server     - OAuth server metadata (RFC 8414)
 * - /.well-known/jwks.json                      - Aggregated JWKS from all realms
 * - /.well-known/oauth-protected-resource/api   - API resource metadata (RFC 9728)
 * - /.well-known/oauth-protected-resource/admin - Admin resource metadata (RFC 9728)
 * - /.well-known/oauth-protected-resource/public - Public resource metadata (RFC 9728)
 * 
 * OAuth Endpoints (route-specific):
 * - /api/auth/login      - Initiate OAuth flow for API realm
 * - /admin/auth/login    - Initiate OAuth flow for Admin realm  
 * - /public/auth/login   - Initiate OAuth flow for Public realm
 * - /api/auth/callback   - OAuth callback for API realm
 * - /admin/auth/callback - OAuth callback for Admin realm
 * - /public/auth/callback - OAuth callback for Public realm
 * 
 * Usage:
 * 1. Set environment variables or update the config below
 * 2. Run: node tests/manual/multi-realm-demo.mjs
 * 3. Server starts on http://localhost:3000
 * 4. Test different realm access patterns
 */

const DEMO_CONFIG = {
    port: 3001,
    keycloakUrl: process.env.KEYCLOAK_URL || 'http://localhost:8080',
    realmsByRoute: {
        '/api': {
            keycloakUrl: process.env.KEYCLOAK_URL || 'http://localhost:8080',
            realm: process.env.API_REALM || 'api-realm',
            clientId: process.env.API_CLIENT_ID || 'api-client',
            clientSecret: process.env.API_CLIENT_SECRET || 'api-secret',
            requiredScopes: [ 'api:read', 'api:write' ],
            resourceUri: 'http://localhost:3001/api'
        },
        '/admin': {
            keycloakUrl: process.env.KEYCLOAK_URL || 'http://localhost:8080',
            realm: process.env.ADMIN_REALM || 'admin-realm',
            clientId: process.env.ADMIN_CLIENT_ID || 'admin-client',
            clientSecret: process.env.ADMIN_CLIENT_SECRET || 'admin-secret',
            requiredScopes: [ 'admin:full' ],
            resourceUri: 'http://localhost:3001/admin'
        },
        '/public': {
            keycloakUrl: process.env.KEYCLOAK_URL || 'http://localhost:8080',
            realm: process.env.PUBLIC_REALM || 'public-realm',
            clientId: process.env.PUBLIC_CLIENT_ID || 'public-client',
            clientSecret: process.env.PUBLIC_CLIENT_SECRET || 'public-secret',
            requiredScopes: [ 'user:basic' ],
            resourceUri: 'http://localhost:3001/public'
        }
    }
}

async function startMultiRealmDemo() {
    console.log( '🚀 Starting Multi-Realm OAuth Middleware Demo Server...' )
    console.log( '' )
    
    try {
        // Create multi-realm OAuth middleware
        console.log( '⚙️  Creating multi-realm OAuth middleware...' )
        const middleware = await OAuthMiddleware.create( {
            realmsByRoute: DEMO_CONFIG.realmsByRoute,
            silent: false // Show verbose logging for demo
        } )
        
        console.log( '✅ Multi-realm middleware created successfully' )
        console.log( '' )
        
        // Create Express app
        const app = express()
        
        // Add middleware for parsing JSON and URL-encoded data
        app.use( express.json() )
        app.use( express.urlencoded( { extended: true } ) )
        
        // Status endpoint (unprotected for health checks) - BEFORE OAuth middleware
        app.get( '/status', ( req, res ) => {
            const routes = middleware.getRoutes()
            const realms = middleware.getRealms()
            
            res.json( {
                status: 'running',
                server: 'Multi-Realm OAuth Demo',
                timestamp: new Date().toISOString(),
                oauth: {
                    routes: routes,
                    realms: realms.map( r => ( {
                        route: r.route,
                        realm: r.realm,
                        keycloakUrl: r.keycloakUrl,
                        scopes: r.requiredScopes
                    } ) ),
                    discoveryEndpoints: [
                        '/.well-known/oauth-authorization-server',
                        '/.well-known/jwks.json',
                        '/.well-known/oauth-protected-resource/api',
                        '/.well-known/oauth-protected-resource/admin',
                        '/.well-known/oauth-protected-resource/public'
                    ]
                }
            } )
        } )
        
        // Add OAuth middleware router (handles all OAuth endpoints and protection)
        app.use( middleware.router() )
        
        // Demo API endpoints (protected by OAuth middleware)
        app.get( '/api', ( req, res ) => {
            res.json( {
                message: 'API endpoint accessed successfully',
                route: '/api',
                realm: 'api-realm',
                requiredScopes: [ 'api:read', 'api:write' ],
                user: req.oauth || null,
                timestamp: new Date().toISOString()
            } )
        } )
        
        app.get( '/api/data', ( req, res ) => {
            res.json( {
                message: 'API data endpoint',
                data: [ 
                    { id: 1, name: 'Resource 1' },
                    { id: 2, name: 'Resource 2' },
                    { id: 3, name: 'Resource 3' }
                ],
                route: '/api/data',
                realm: 'api-realm',
                user: req.oauth || null
            } )
        } )
        
        app.get( '/admin', ( req, res ) => {
            res.json( {
                message: 'Admin endpoint accessed successfully',
                route: '/admin',
                realm: 'admin-realm',
                requiredScopes: [ 'admin:full' ],
                user: req.oauth || null,
                timestamp: new Date().toISOString()
            } )
        } )
        
        app.get( '/admin/users', ( req, res ) => {
            res.json( {
                message: 'Admin users endpoint',
                users: [
                    { id: 1, username: 'admin', role: 'administrator' },
                    { id: 2, username: 'user1', role: 'user' },
                    { id: 3, username: 'user2', role: 'user' }
                ],
                route: '/admin/users',
                realm: 'admin-realm',
                user: req.oauth || null
            } )
        } )
        
        app.get( '/public', ( req, res ) => {
            res.json( {
                message: 'Public endpoint accessed successfully',
                route: '/public',
                realm: 'public-realm',
                requiredScopes: [ 'user:basic' ],
                user: req.oauth || null,
                timestamp: new Date().toISOString()
            } )
        } )
        
        app.get( '/public/info', ( req, res ) => {
            res.json( {
                message: 'Public info endpoint',
                info: {
                    serverName: 'Multi-Realm Demo Server',
                    version: '1.0.0',
                    supportedRealms: [ 'api-realm', 'admin-realm', 'public-realm' ],
                    features: [ 'OAuth 2.1', 'Multi-Realm', 'RFC Compliance' ]
                },
                route: '/public/info',
                realm: 'public-realm',
                user: req.oauth || null
            } )
        } )
        
        
        // Start server
        const server = app.listen( DEMO_CONFIG.port, () => {
            console.log( '🎉 Multi-Realm OAuth Demo Server is running!' )
            console.log( '' )
            console.log( '📍 Server Details:' )
            console.log( `   URL: http://localhost:${DEMO_CONFIG.port}` )
            console.log( `   Keycloak: ${DEMO_CONFIG.keycloakUrl}` )
            console.log( '' )
            
            console.log( '🛡️  Protected Routes:' )
            console.log( '   📁 /api/*     → api-realm     (api:read, api:write)' )
            console.log( '   🔧 /admin/*   → admin-realm   (admin:full)' )
            console.log( '   👤 /public/*  → public-realm  (user:basic)' )
            console.log( '' )
            
            console.log( '🔍 Discovery Endpoints:' )
            console.log( '   📋 /.well-known/oauth-authorization-server' )
            console.log( '   🔑 /.well-known/jwks.json' )
            console.log( '   📋 /.well-known/oauth-protected-resource/api' )
            console.log( '   📋 /.well-known/oauth-protected-resource/admin' )
            console.log( '   📋 /.well-known/oauth-protected-resource/public' )
            console.log( '' )
            
            console.log( '🔐 OAuth Flow Endpoints:' )
            console.log( '   🔗 /api/auth/login       → Start API OAuth flow' )
            console.log( '   🔗 /admin/auth/login     → Start Admin OAuth flow' )
            console.log( '   🔗 /public/auth/login    → Start Public OAuth flow' )
            console.log( '   ↩️  /*/auth/callback      → OAuth callback handler' )
            console.log( '' )
            
            console.log( '🧪 Test Endpoints:' )
            console.log( '   ℹ️  GET /status           → Server status (unprotected)' )
            console.log( '   📊 GET /api              → API endpoint (protected)' )
            console.log( '   📊 GET /api/data         → API data (protected)' )
            console.log( '   🔧 GET /admin            → Admin endpoint (protected)' )
            console.log( '   🔧 GET /admin/users      → Admin users (protected)' )
            console.log( '   👤 GET /public           → Public endpoint (protected)' )
            console.log( '   👤 GET /public/info      → Public info (protected)' )
            console.log( '' )
            
            console.log( '💡 Quick Test:' )
            console.log( '   curl http://localhost:3001/status' )
            console.log( '   curl http://localhost:3001/.well-known/oauth-authorization-server' )
            console.log( '   curl http://localhost:3001/api  # Should redirect to OAuth' )
            console.log( '' )
            
            console.log( '🌟 Features Demonstrated:' )
            console.log( '   ✅ Multi-realm OAuth architecture' )
            console.log( '   ✅ Route-to-realm mapping' )
            console.log( '   ✅ RFC 8414 Authorization Server Metadata' )
            console.log( '   ✅ RFC 9728 Protected Resource Metadata' )
            console.log( '   ✅ RFC 8707 Resource Indicators' )
            console.log( '   ✅ OAuth 2.1 Security (HTTPS, PKCE, Bearer tokens)' )
            console.log( '   ✅ Automatic JWKS aggregation' )
            console.log( '   ✅ Audience binding validation' )
            console.log( '' )
        } )
        
        // Graceful shutdown
        process.on( 'SIGTERM', () => {
            console.log( '🛑 Received SIGTERM, shutting down gracefully...' )
            server.close( () => {
                console.log( '✅ Server closed successfully' )
                process.exit( 0 )
            } )
        } )
        
        process.on( 'SIGINT', () => {
            console.log( '🛑 Received SIGINT, shutting down gracefully...' )
            server.close( () => {
                console.log( '✅ Server closed successfully' )
                process.exit( 0 )
            } )
        } )
        
    } catch( error ) {
        console.error( '❌ Failed to start multi-realm demo server:' )
        console.error( `   Error: ${error.message}` )
        console.error( '' )
        console.error( '🔧 Troubleshooting:' )
        console.error( '   1. Check Keycloak server is running' )
        console.error( '   2. Verify realm and client configurations' )
        console.error( '   3. Ensure environment variables are set' )
        console.error( '   4. Check network connectivity' )
        console.error( '' )
        process.exit( 1 )
    }
}

// Start the demo server
startMultiRealmDemo()