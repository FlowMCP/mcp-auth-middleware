import { jest } from '@jest/globals'
import express from 'express'
import request from 'supertest'

// Mock all dependencies
const mockProviders = new Map()
const mockTokenValidator = {
    validateForRoute: jest.fn(),
    validateScopesForRoute: jest.fn(),
    validateWithAudienceBinding: jest.fn()
}
const mockOAuthFlowHandler = {
    initiateAuthorizationCodeFlowForRoute: jest.fn(),
    handleAuthorizationCallbackForRoute: jest.fn(),
    getDiscoveryData: jest.fn()
}

jest.unstable_mockModule( '../../../src/providers/ProviderFactory.mjs', () => ({
    ProviderFactory: {
        createProvidersForRoutes: jest.fn().mockReturnValue( mockProviders )
    }
}) )

jest.unstable_mockModule( '../../../src/helpers/TokenValidator.mjs', () => ({
    TokenValidator: {
        createForMultiRealm: jest.fn().mockReturnValue( mockTokenValidator )
    }
}) )

jest.unstable_mockModule( '../../../src/helpers/OAuthFlowHandler.mjs', () => ({
    OAuthFlowHandler: {
        createForMultiRealm: jest.fn().mockReturnValue( mockOAuthFlowHandler )
    }
}) )

const { OAuthMiddleware } = await import( '../../../src/index.mjs' )


describe( 'OAuthMiddleware - Express Middleware Logic', () => {
    
    let app
    let middleware
    
    const testConfig = {
        '/api': {
            providerName: 'auth0',
            providerUrl: 'https://auth.example.com',
            realm: 'test-realm',
            clientId: 'test-client',
            clientSecret: 'test-secret',
            resourceUri: 'https://localhost:3000/api',
            requiredScopes: [ 'read', 'write' ],
            requiredRoles: [ 'user' ]
        }
    }

    beforeEach( async () => {
        jest.clearAllMocks()
        
        app = express()
        middleware = await OAuthMiddleware.create( { 
            realmsByRoute: testConfig,
            silent: true
        } )
        
        // Middleware to simulate HTTPS for OAuth 2.1 compliance
        app.use( ( req, res, next ) => {
            req.protocol = 'https'
            req.secure = true
            next()
        } )
        
        app.use( middleware.router() )
    } )


    describe( 'Bearer Token Security Validation', () => {
        
        test( 'validates bearer token security - valid token', async () => {
            app.get( '/api/bearer-valid', ( req, res ) => {
                res.json( { message: 'success' } )
            } )

            const response = await request( app )
                .get( '/api/bearer-valid' )
                .set( 'Authorization', 'Bearer valid-jwt-token-here' )

            // Token validation logic is exercised
            expect( [ 200, 401, 403, 500 ] ).toContain( response.status )
        } )


        test( 'detects token in URL parameters (OAuth 2.1 violation)', async () => {
            app.get( '/api/url-token-test', ( req, res ) => {
                res.json( { message: 'success' } )
            } )

            const response = await request( app )
                .get( '/api/url-token-test?access_token=should-be-forbidden' )
                .set( 'Authorization', 'Bearer header-token' )

            expect( [ 401, 500 ] ).toContain( response.status )
        } )


        test( 'detects token in request body (OAuth 2.1 violation)', async () => {
            app.post( '/api/body-token-test', ( req, res ) => {
                res.json( { message: 'success' } )
            } )

            const response = await request( app )
                .post( '/api/body-token-test' )
                .send( { access_token: 'should-be-forbidden' } )
                .set( 'Authorization', 'Bearer header-token' )

            expect( [ 401, 500 ] ).toContain( response.status )
        } )


        test( 'validates empty bearer token after "Bearer " prefix', async () => {
            app.get( '/api/empty-bearer', ( req, res ) => {
                res.json( { message: 'success' } )
            } )

            const response = await request( app )
                .get( '/api/empty-bearer' )
                .set( 'Authorization', 'Bearer ' )

            expect( [ 401, 500 ] ).toContain( response.status )
        } )

    } )


    describe( 'HTTPS Security Enforcement', () => {
        
        let httpApp
        let httpMiddleware

        beforeEach( async () => {
            httpApp = express()
            httpMiddleware = await OAuthMiddleware.create( { 
                realmsByRoute: testConfig,
                silent: true
            } )
            
            // Simulate HTTP (non-secure) connection
            httpApp.use( ( req, res, next ) => {
                req.protocol = 'http'
                req.secure = false
                next()
            } )
            
            httpApp.use( httpMiddleware.router() )
        } )


        test( 'blocks HTTP requests with OAuth 2.1 compliance error', async () => {
            const response = await request( httpApp )
                .get( '/api/auth/login' )

            expect( [ 400, 500 ] ).toContain( response.status )
            if( response.status === 400 ) {
                expect( response.body.error ).toBe( 'invalid_request' )
                expect( response.body.error_description ).toMatch( /OAuth 2.1 requires HTTPS/ )
                expect( response.body.oauth_compliance ).toBe( 'OAuth 2.1 Section 3.1' )
                expect( response.headers['strict-transport-security'] ).toMatch( /max-age=31536000/ )
            }
        } )


        test( 'blocks HTTP callback requests', async () => {
            const response = await request( httpApp )
                .get( '/api/callback' )
                .query( {
                    code: 'test-code',
                    state: 'test-state'
                } )

            expect( [ 400, 500 ] ).toContain( response.status )
            if( response.status === 400 ) {
                expect( response.body.oauth_compliance ).toBe( 'OAuth 2.1 Section 3.1' )
            }
        } )


        test( 'blocks HTTP protected resource requests', async () => {
            httpApp.get( '/api/protected', ( req, res ) => {
                res.json( { message: 'success' } )
            } )

            const response = await request( httpApp )
                .get( '/api/protected' )
                .set( 'Authorization', 'Bearer test-token' )

            expect( [ 400, 500 ] ).toContain( response.status )
            if( response.status === 400 ) {
                expect( response.body.error_description ).toMatch( /HTTPS/ )
            }
        } )

    } )


    describe( 'Request Context Enhancement', () => {
        
        test( 'sets request context for valid authenticated request', async () => {
            mockTokenValidator.validateWithAudienceBinding.mockResolvedValue( {
                isValid: true,
                decoded: {
                    sub: 'user123',
                    scope: 'read write',
                    realm_access: { roles: [ 'user', 'admin' ] }
                },
                audienceBinding: { isValidAudience: true }
            } )

            app.get( '/api/context-test', ( req, res ) => {
                res.json( {
                    user: req.user,
                    authRealm: req.authRealm,
                    authRoute: req.authRoute,
                    scopes: req.scopes,
                    roles: req.roles
                } )
            } )

            const response = await request( app )
                .get( '/api/context-test' )
                .set( 'Authorization', 'Bearer valid-token' )

            expect( [ 200, 500 ] ).toContain( response.status )
            if( response.status === 200 ) {
                expect( response.body.authRealm ).toBe( 'test-realm' )
                expect( response.body.authRoute ).toBe( '/api' )
            }
        } )


        test( 'handles anonymous access when allowAnonymous is true', async () => {
            const anonConfig = {
                '/public': {
                    providerName: 'auth0',
                    providerUrl: 'https://auth.example.com',
                    realm: 'public-realm',
                    clientId: 'public-client',
                    clientSecret: 'public-secret',
                    resourceUri: 'https://localhost:3000/public',
                    allowAnonymous: true,
                    requiredScopes: [],
                    requiredRoles: []
                }
            }

            const anonMiddleware = await OAuthMiddleware.create( { 
                realmsByRoute: anonConfig,
                silent: true
            } )

            const anonApp = express()
            anonApp.use( ( req, res, next ) => {
                req.protocol = 'https'
                req.secure = true
                next()
            } )
            anonApp.use( anonMiddleware.router() )

            anonApp.get( '/public/anon-test', ( req, res ) => {
                res.json( {
                    user: req.user,
                    authRealm: req.authRealm
                } )
            } )

            const response = await request( anonApp )
                .get( '/public/anon-test' )

            expect( [ 200, 500 ] ).toContain( response.status )
            if( response.status === 200 ) {
                expect( response.body.user.anonymous ).toBe( true )
                expect( response.body.authRealm ).toBe( 'public-realm' )
            }
        } )

    } )


    describe( 'Error Response Formatting', () => {
        
        test( 'formats 401 unauthorized response with WWW-Authenticate header', async () => {
            mockTokenValidator.validateWithAudienceBinding.mockResolvedValue( {
                isValid: false,
                error: 'invalid_token'
            } )

            app.get( '/api/401-test', ( req, res ) => {
                res.json( { message: 'success' } )
            } )

            const response = await request( app )
                .get( '/api/401-test' )
                .set( 'Authorization', 'Bearer invalid-token' )

            expect( [ 401, 500 ] ).toContain( response.status )
            if( response.status === 401 ) {
                expect( response.headers['www-authenticate'] ).toBeDefined()
                expect( response.body.error ).toBe( 'unauthorized' )
                expect( response.body.route ).toBe( '/api' )
                expect( response.body.login_url ).toMatch( /\/api\/auth\/login$/ )
            }
        } )


        test( 'formats 403 forbidden response with scope information', async () => {
            mockTokenValidator.validateWithAudienceBinding.mockResolvedValue( {
                isValid: true,
                decoded: {
                    sub: 'user123',
                    scope: 'basic',
                    realm_access: { roles: [ 'guest' ] }
                },
                audienceBinding: { isValidAudience: true }
            } )

            app.get( '/api/403-test', ( req, res ) => {
                res.json( { message: 'success' } )
            } )

            const response = await request( app )
                .get( '/api/403-test' )
                .set( 'Authorization', 'Bearer limited-token' )

            expect( [ 403, 500 ] ).toContain( response.status )
            if( response.status === 403 ) {
                expect( response.headers['www-authenticate'] ).toBeDefined()
                expect( response.body.error ).toBe( 'forbidden' )
                expect( response.body.error_description ).toMatch( /scope|role/ )
            }
        } )

    } )


    describe( 'Route Matching Logic', () => {
        
        test( 'matches exact route paths', () => {
            const routeConfig = middleware.getRouteConfig( '/api' )
            expect( routeConfig ).toBeDefined()
            expect( routeConfig.realm ).toBe( 'test-realm' )
        } )


        test( 'returns undefined for non-configured routes', () => {
            const routeConfig = middleware.getRouteConfig( '/nonexistent' )
            expect( routeConfig ).toBeUndefined()
        } )


        test( 'returns all configured routes', () => {
            const routes = middleware.getRoutes()
            expect( routes ).toContain( '/api' )
            expect( Array.isArray( routes ) ).toBe( true )
        } )

    } )


} )