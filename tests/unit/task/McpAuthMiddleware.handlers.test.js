import { jest } from '@jest/globals'
import express from 'express'
import request from 'supertest'

const { McpAuthMiddleware } = await import( '../../../src/index.mjs' )

// Helper to create complete OAuth21 Auth0 config
const createCompleteConfig = (overrides = {}) => ({
    authType: 'oauth21_auth0',
    providerUrl: 'https://tenant.auth0.com',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    scope: 'openid profile email api:read',
    audience: 'https://api.example.com',
    realm: 'test-realm',
    authFlow: 'authorization_code',
    requiredScopes: [ 'openid', 'profile', 'email', 'api:read' ],
    requiredRoles: [ 'user' ],
    ...overrides
})


describe( 'McpAuthMiddleware - HTTP Handlers', () => {
    
    let app
    let middleware
    
    const testConfig = {
        routes: {
            '/api': createCompleteConfig()
        },
        silent: true
    }

    beforeEach( async () => {
        jest.clearAllMocks()
        
        app = express()
        middleware = await McpAuthMiddleware.create( testConfig )
        
        // Mock HTTPS for testing handlers (must come BEFORE router)
        app.use( ( req, res, next ) => {
            // Use Object.defineProperty to override read-only properties
            Object.defineProperty( req, 'protocol', { 
                value: 'https', 
                configurable: true, 
                writable: true 
            } )
            Object.defineProperty( req, 'secure', { 
                value: true, 
                configurable: true, 
                writable: true 
            } )
            next()
        } )
        
        app.use( middleware.router() )
    } )


    describe( 'OAuth Authorization Flow Handlers', () => {
        
        test( 'login endpoint initiates authorization flow', async () => {
            const response = await request( app )
                .get( '/api/auth/login' )
                
            // Should redirect to Auth0 authorization server (302)
            expect( response.status ).toBe( 302 )
            expect( response.headers.location ).toContain( 'https://tenant.auth0.com/authorize' )
            expect( response.headers.location ).toContain( 'client_id=test-client-id' )
        } )

        test( 'callback endpoint handles authorization response', async () => {
            // Without valid OAuth state/code, should return error  
            const response = await request( app )
                .get( '/api/auth/callback' )
                .query( {
                    code: 'invalid-mock-auth-code',
                    state: 'invalid-mock-state'
                } )

            // Should return error for invalid code (Auth0 will reject it)
            expect( response.status ).toBeGreaterThanOrEqual( 400 )
        } )

        test( 'callback endpoint handles error responses', async () => {
            const response = await request( app )
                .get( '/api/auth/callback' )
                .query( {
                    error: 'access_denied',
                    error_description: 'User denied access'
                } )

            expect( response.status ).toBeGreaterThanOrEqual( 400 )
            expect( response.body ).toHaveProperty( 'error', 'access_denied' )
        } )

    } )


    describe( 'Discovery Endpoints', () => {
        
        test( 'well-known authorization server endpoint', async () => {
            const response = await request( app )
                .get( '/.well-known/oauth-authorization-server' )

            // Should return proper discovery metadata
            expect( response.status ).toBe( 200 )
            expect( response.headers['content-type'] ).toContain( 'application/json' )
            expect( response.body ).toHaveProperty( 'issuer' )
            expect( response.body ).toHaveProperty( 'authorization_endpoint' )
            expect( response.body ).toHaveProperty( 'token_endpoint' )
            
            // Verify actual Auth0 endpoints
            expect( response.body.issuer ).toBe( 'https://tenant.auth0.com' )
            expect( response.body.authorization_endpoint ).toContain( 'tenant.auth0.com' )
        } )

        test( 'JWKS endpoint provides public keys structure', async () => {
            const response = await request( app )
                .get( '/.well-known/jwks.json' )

            // Should return proper JWKS structure even if no keys from fake domain
            expect( response.status ).toBe( 200 )
            expect( response.headers['content-type'] ).toContain( 'application/json' )
            expect( response.body ).toHaveProperty( 'keys' )
            expect( Array.isArray( response.body.keys ) ).toBe( true )
            
            // For fake Auth0 domain, keys array may be empty (expected behavior)
            // Real Auth0 domains would have keys, but tenant.auth0.com is fake
            if( response.body.keys.length > 0 ) {
                const firstKey = response.body.keys[0]
                expect( firstKey ).toHaveProperty( 'kty' )
                expect( firstKey ).toHaveProperty( 'use' )
                expect( firstKey ).toHaveProperty( 'kid' )
            }
        } )

    } )


    describe( 'Route-Specific Handlers', () => {
        
        test( 'different routes have independent handlers', async () => {
            const multiRouteMiddleware = await McpAuthMiddleware.create( {
                routes: {
                    '/api': createCompleteConfig({
                        providerUrl: 'https://api.auth0.com',
                        clientId: 'api-client-id',
                        clientSecret: 'api-client-secret',
                        scope: 'openid profile email api:read',
                        audience: 'https://api.example.com'
                    }),
                    '/admin': createCompleteConfig({
                        providerUrl: 'https://admin.auth0.com',
                        clientId: 'admin-client-id',
                        clientSecret: 'admin-client-secret',
                        scope: 'openid profile email admin:full',
                        audience: 'https://admin.example.com'
                    })
                },
                silent: true
            } )

            const multiApp = express()
            multiApp.use( ( req, res, next ) => {
                // Use Object.defineProperty to override read-only properties
                Object.defineProperty( req, 'protocol', { 
                    value: 'https', 
                    configurable: true, 
                    writable: true 
                } )
                Object.defineProperty( req, 'secure', { 
                    value: true, 
                    configurable: true, 
                    writable: true 
                } )
                next()
            } )
            multiApp.use( multiRouteMiddleware.router() )

            // Both routes should redirect to their respective Auth0 domains
            const apiResponse = await request( multiApp ).get( '/api/auth/login' )
            const adminResponse = await request( multiApp ).get( '/admin/auth/login' )

            // Should be redirects (302) to different Auth0 tenants
            expect( apiResponse.status ).toBe( 302 )
            expect( adminResponse.status ).toBe( 302 )
            
            // Should redirect to different providers
            expect( apiResponse.headers.location ).toContain( 'api.auth0.com' )
            expect( adminResponse.headers.location ).toContain( 'admin.auth0.com' )
        } )

    } )


    describe( 'Error Handling in Handlers', () => {
        
        test( 'handles missing parameters in callback gracefully', async () => {
            // Test callback without required code/state parameters
            const response = await request( app )
                .get( '/api/auth/callback' )
                // Missing required parameters

            expect( response.status ).toBeGreaterThanOrEqual( 400 )
            expect( response.headers['content-type'] ).toContain( 'json' )
            expect( response.body ).toHaveProperty( 'error' )
        } )

        test( 'returns proper error for non-existent routes', async () => {
            const response = await request( app )
                .get( '/nonexistent/auth/login' )

            expect( response.status ).toBe( 404 )
        } )

        test( 'handles POST requests to callback endpoints', async () => {
            // OAuth 2.1 supports both GET and POST for callbacks
            const response = await request( app )
                .post( '/api/auth/callback' )
                .send( {
                    code: 'invalid-code',
                    state: 'invalid-state'
                } )

            expect( response.status ).toBeGreaterThanOrEqual( 400 )
            expect( response.body ).toHaveProperty( 'error' )
        } )

    } )

} )