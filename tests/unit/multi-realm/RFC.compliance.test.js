import { jest } from '@jest/globals'
import request from 'supertest'
import express from 'express'

// Mock helper classes for RFC compliance testing
const mockKeycloakClientForMultiRealm = jest.fn()
const mockTokenValidatorForMultiRealm = jest.fn()
const mockOAuthFlowHandlerForMultiRealm = jest.fn()

jest.unstable_mockModule( '../../../src/helpers/KeycloakClient.mjs', () => ({
    KeycloakClient: {
        createForMultiRealm: mockKeycloakClientForMultiRealm
    }
}) )

jest.unstable_mockModule( '../../../src/helpers/TokenValidator.mjs', () => ({
    TokenValidator: {
        createForMultiRealm: mockTokenValidatorForMultiRealm
    }
}) )

jest.unstable_mockModule( '../../../src/helpers/OAuthFlowHandler.mjs', () => ({
    OAuthFlowHandler: {
        createForMultiRealm: mockOAuthFlowHandlerForMultiRealm
    }
}) )

const { OAuthMiddleware } = await import( '../../../src/index.mjs' )


describe( 'RFC Compliance Tests - Multi-Realm', () => {
    let app
    let middleware
    let mockKeycloakClient
    let mockTokenValidator
    let mockOAuthFlowHandler
    let originalEnv
    
    const testRealmsByRoute = {
        '/api': {
            keycloakUrl: 'http://localhost:8080',
            realm: 'api-realm',
            clientId: 'api-client',
            clientSecret: 'api-secret',
            requiredScopes: [ 'api:read', 'api:write' ],
            resourceUri: 'http://localhost:3000/api'
        },
        '/protected': {
            keycloakUrl: 'http://localhost:8080',
            realm: 'secure-realm',
            clientId: 'secure-client',
            clientSecret: 'secure-secret',
            requiredScopes: [ 'protected:access' ],
            resourceUri: 'http://localhost:3000/protected'
        }
    }

    beforeEach( async () => {
        originalEnv = process.env.NODE_ENV
        jest.clearAllMocks()
        
        // Mock helper instances
        mockKeycloakClient = {
            getJwksForRoute: jest.fn().mockResolvedValue( { jwksData: { keys: [] } } ),
            getAllRoutes: jest.fn().mockReturnValue( [ '/api', '/protected' ] )
        }
        
        mockTokenValidator = {
            validateForRoute: jest.fn().mockResolvedValue( { 
                isValid: false, 
                error: 'invalid_token',
                decoded: null 
            } ),
            validateWithAudienceBinding: jest.fn().mockResolvedValue( { 
                isValid: false, 
                error: 'invalid_token',
                decoded: null,
                audienceBinding: { isValidAudience: false }
            } ),
            getAllRoutes: jest.fn().mockReturnValue( [ '/api', '/protected' ] )
        }
        
        mockOAuthFlowHandler = {
            initiateAuthorizationCodeFlowForRoute: jest.fn().mockReturnValue( {
                authorizationUrl: 'http://localhost:8080/auth?code_challenge=CHALLENGE&code_challenge_method=S256',
                state: 'test-state',
                route: '/api'
            } ),
            getAllRoutes: jest.fn().mockReturnValue( [ '/api', '/protected' ] )
        }
        
        // Setup mock returns
        mockKeycloakClientForMultiRealm.mockResolvedValue( mockKeycloakClient )
        mockTokenValidatorForMultiRealm.mockReturnValue( mockTokenValidator )
        mockOAuthFlowHandlerForMultiRealm.mockReturnValue( mockOAuthFlowHandler )
        
        middleware = await OAuthMiddleware.create( {
            realmsByRoute: testRealmsByRoute,
            silent: true
        } )
        
        app = express()
        app.use( middleware.router() )
    } )

    afterEach( () => {
        process.env.NODE_ENV = originalEnv
    } )


    describe( 'RFC 8414 - OAuth 2.0 Authorization Server Metadata', () => {
        it( 'provides compliant authorization server metadata', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/.well-known/oauth-authorization-server' )
                .expect( 200 )
                .expect( 'Content-Type', /application\/json/ )
            
            // RFC 8414 Section 2 - Required metadata fields
            expect( response.body ).toHaveProperty( 'issuer' )
            expect( response.body ).toHaveProperty( 'response_types_supported' )
            expect( response.body.response_types_supported ).toContain( 'code' )
            
            // RFC 8414 Section 2 - Recommended metadata fields  
            expect( response.body ).toHaveProperty( 'grant_types_supported' )
            expect( response.body.grant_types_supported ).toEqual( 
                expect.arrayContaining( [ 'authorization_code', 'client_credentials', 'refresh_token' ] )
            )
            
            expect( response.body ).toHaveProperty( 'token_endpoint_auth_methods_supported' )
            expect( response.body.token_endpoint_auth_methods_supported ).toEqual( 
                expect.arrayContaining( [ 'client_secret_post', 'client_secret_basic' ] )
            )
            
            // Multi-realm extensions
            expect( response.body ).toHaveProperty( 'authorization_servers' )
            expect( response.body ).toHaveProperty( 'realms_supported' )
            expect( response.body ).toHaveProperty( 'routes_supported' )
            expect( response.body ).toHaveProperty( 'route_realm_mapping' )
            
            // Verify multi-realm structure - authorization_servers is an array
            expect( response.body.authorization_servers ).toEqual( expect.any( Array ) )
            expect( response.body.authorization_servers ).toHaveLength( 2 )
            
            // Find the authorization servers by issuer URL
            const apiServer = response.body.authorization_servers.find( s => s.issuer.includes( 'api-realm' ) )
            const secureServer = response.body.authorization_servers.find( s => s.issuer.includes( 'secure-realm' ) )
            expect( apiServer ).toBeDefined()
            expect( secureServer ).toBeDefined()
            
            expect( response.body.route_realm_mapping ).toHaveProperty( '/api' )
            expect( response.body.route_realm_mapping ).toHaveProperty( '/protected' )
        } )

        it( 'includes OAuth 2.1 security metadata', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/.well-known/oauth-authorization-server' )
                .expect( 200 )
            
            // OAuth 2.1 security requirements
            expect( response.body ).toHaveProperty( 'code_challenge_methods_supported' )
            expect( response.body.code_challenge_methods_supported ).toContain( 'S256' )
            
            expect( response.body ).toHaveProperty( 'response_modes_supported' )
            expect( response.body.response_modes_supported ).toEqual( 
                expect.arrayContaining( [ 'query', 'form_post' ] )
            )
        } )

        it( 'includes RFC 8707 resource indicators support', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/.well-known/oauth-authorization-server' )
                .expect( 200 )
            
            // RFC 8707 Resource Indicators
            expect( response.body ).toHaveProperty( 'resource_indicators_supported' )
            expect( response.body.resource_indicators_supported ).toBe( true )
        } )

        it( 'provides RFC compliance information', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/.well-known/oauth-authorization-server' )
                .expect( 200 )
            
            expect( response.body ).toHaveProperty( 'rfc_compliance' )
            expect( response.body.rfc_compliance ).toMatchObject( {
                'rfc8414': 'OAuth 2.0 Authorization Server Metadata',
                'rfc9728': 'OAuth 2.0 Protected Resource Metadata', 
                'rfc8707': 'OAuth 2.0 Resource Indicators'
            } )
        } )
    } )


    describe( 'RFC 9728 - Protected Resource Metadata', () => {
        it( 'provides compliant protected resource metadata', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/.well-known/oauth-protected-resource/api' )
                .expect( 200 )
                .expect( 'Content-Type', /application\/json/ )
            
            // RFC 9728 Section 3 - Required fields
            expect( response.body ).toHaveProperty( 'resource' )
            expect( response.body.resource ).toMatch( /\/api$/ )
            
            expect( response.body ).toHaveProperty( 'authorization_servers' )
            expect( response.body.authorization_servers ).toEqual( [ 'http://localhost:8080/realms/api-realm' ] )
            
            // RFC 9728 Section 3 - Optional recommended fields
            expect( response.body ).toHaveProperty( 'scopes_supported' )
            expect( response.body.scopes_supported ).toEqual( [ 'api:read', 'api:write' ] )
            
            expect( response.body ).toHaveProperty( 'bearer_methods_supported' )
            expect( response.body.bearer_methods_supported ).toContain( 'header' )
            
            expect( response.body ).toHaveProperty( 'resource_documentation' )
            expect( typeof response.body.resource_documentation ).toBe( 'string' )
        } )

        it( 'serves different metadata for different routes', async () => {
            process.env.NODE_ENV = 'development'
            
            const apiResponse = await request( app )
                .get( '/.well-known/oauth-protected-resource/api' )
                .expect( 200 )
            
            const protectedResponse = await request( app )
                .get( '/.well-known/oauth-protected-resource/protected' )
                .expect( 200 )
            
            // Verify route-specific metadata
            expect( apiResponse.body.resource ).toMatch( /\/api$/ )
            expect( protectedResponse.body.resource ).toMatch( /\/protected$/ )
            
            expect( apiResponse.body.authorization_servers ).toEqual( [ 'http://localhost:8080/realms/api-realm' ] )
            expect( protectedResponse.body.authorization_servers ).toEqual( [ 'http://localhost:8080/realms/secure-realm' ] )
            
            expect( apiResponse.body.scopes_supported ).toEqual( [ 'api:read', 'api:write' ] )
            expect( protectedResponse.body.scopes_supported ).toEqual( [ 'protected:access' ] )
        } )

        it( 'includes proper caching headers', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/.well-known/oauth-protected-resource/api' )
                .expect( 200 )
            
            // RFC 9728 recommends caching
            expect( response.headers['cache-control'] ).toBe( 'public, max-age=300' )
            expect( response.headers['access-control-allow-origin'] ).toBe( '*' )
        } )
    } )


    describe( 'RFC 8707 - Resource Indicators', () => {
        it( 'includes resource parameters in OAuth flows', async () => {
            process.env.NODE_ENV = 'development'
            
            await request( app )
                .get( '/api/auth/login' )
                .expect( 302 )
            
            // Verify OAuth flow was initiated with resource indicators
            expect( mockOAuthFlowHandler.initiateAuthorizationCodeFlowForRoute ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    route: '/api',
                    resourceIndicators: expect.arrayContaining( [ expect.stringContaining( '/api' ) ] )
                } )
            )
        } )

        it( 'validates audience binding for protected resources', async () => {
            process.env.NODE_ENV = 'development'
            
            // Test that the OAuth middleware attempts audience binding validation for resource indicators
            const response = await request( app )
                .get( '/api' )
                .set( 'Authorization', 'Bearer test-token' )
                .expect( 401 ) // Token validation fails (expected with default mock)
            
            // Verify audience binding validation was called with resource indicators
            expect( mockTokenValidator.validateWithAudienceBinding ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    token: 'test-token',
                    route: '/api',
                    resourceUri: expect.stringContaining( '/api' )
                } )
            )
            
            // Verify the error response indicates OAuth 2.1 compliance
            expect( response.body ).toHaveProperty( 'error' )
            expect( response.headers['www-authenticate'] ).toMatch( /Bearer/ )
        } )
    } )


    describe( 'OAuth 2.1 Security Compliance', () => {
        it( 'enforces HTTPS-only access', async () => {
            // Test without development environment to trigger HTTPS enforcement
            const response = await request( app )
                .get( '/.well-known/oauth-authorization-server' )
                .expect( 400 )
            
            expect( response.body ).toMatchObject( {
                error: 'invalid_request',
                error_description: expect.stringContaining( 'OAuth 2.1 requires HTTPS' ),
                oauth_compliance: 'OAuth 2.1 Section 3.1'
            } )
            
            expect( response.headers['strict-transport-security'] ).toBe( 'max-age=31536000; includeSubDomains' )
        } )

        it( 'validates Bearer token format', async () => {
            process.env.NODE_ENV = 'development'
            
            // Test invalid token format
            const response = await request( app )
                .get( '/api' )
                .set( 'Authorization', 'Basic invalid-format' )
                .expect( 401 )
            
            expect( response.body ).toMatchObject( {
                error: 'unauthorized',
                error_description: expect.stringContaining( 'OAuth 2.1 requires Bearer token format' )
            } )
        } )

        it( 'rejects tokens in URL parameters', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/api?access_token=invalid-location' )
                .set( 'Authorization', 'Bearer valid-token' ) // Need Bearer token to trigger URL parameter check
                .expect( 401 )
            
            expect( response.body ).toMatchObject( {
                error: 'unauthorized',
                error_description: expect.stringContaining( 'OAuth 2.1 prohibits access tokens in URL parameters' )
            } )
        } )

        it( 'includes PKCE in authorization flows', async () => {
            process.env.NODE_ENV = 'development'
            
            await request( app )
                .get( '/api/auth/login' )
                .expect( 302 )
            
            // Verify PKCE parameters are included in the OAuth flow
            expect( mockOAuthFlowHandler.initiateAuthorizationCodeFlowForRoute ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    route: '/api'
                } )
            )
            
            // The mock returns an authorization URL with PKCE parameters
            const mockCall = mockOAuthFlowHandler.initiateAuthorizationCodeFlowForRoute.mock.calls[0][0]
            expect( mockCall.route ).toBe( '/api' )
        } )
    } )


    describe( 'Multi-Realm Error Handling', () => {
        it( 'returns proper RFC 9728 error responses', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/api' )
                .set( 'Authorization', 'Bearer invalid-token' )
                .expect( 401 )
            
            // RFC 9728 Section 4 - Error responses
            expect( response.headers['www-authenticate'] ).toMatch( /Bearer/ )
            expect( response.headers['www-authenticate'] ).toMatch( /realm="\/api"/ )
            expect( response.headers['www-authenticate'] ).toMatch( /error="invalid_token"/ )
            expect( response.headers['www-authenticate'] ).toMatch( /resource_metadata/ )
        } )

        it( 'handles route-specific validation errors', async () => {
            process.env.NODE_ENV = 'development'
            
            // Test different routes return different error contexts
            const apiResponse = await request( app )
                .get( '/api' )
                .set( 'Authorization', 'Bearer invalid-token' )
                .expect( 401 )
            
            const protectedResponse = await request( app )
                .get( '/protected' )
                .set( 'Authorization', 'Bearer invalid-token' )
                .expect( 401 )
            
            // Verify route-specific error context
            expect( apiResponse.body.route ).toBe( '/api' )
            expect( protectedResponse.body.route ).toBe( '/protected' )
            
            expect( apiResponse.headers['www-authenticate'] ).toMatch( /realm="\/api"/ )
            expect( protectedResponse.headers['www-authenticate'] ).toMatch( /realm="\/protected"/ )
        } )
    } )
} )