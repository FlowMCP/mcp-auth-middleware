import { jest } from '@jest/globals'
import request from 'supertest'
import express from 'express'

// Mock helper classes for discovery testing
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


describe( 'Multi-Realm Discovery Endpoints', () => {
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
            requiredScopes: [ 'api:read' ],
            resourceUri: 'http://localhost:3000/api'
        },
        '/admin': {
            keycloakUrl: 'http://localhost:8080',
            realm: 'admin-realm', 
            clientId: 'admin-client',
            clientSecret: 'admin-secret',
            requiredScopes: [ 'admin:full' ],
            resourceUri: 'http://localhost:3000/admin'
        }
    }

    beforeEach( async () => {
        // Store original environment
        originalEnv = process.env.NODE_ENV
        
        // Reset mocks
        jest.clearAllMocks()
        
        // Mock JWKS data for different realms
        const mockApiJwks = {
            keys: [ { 
                kid: 'api-key-1', 
                kty: 'RSA', 
                use: 'sig',
                n: 'api-key-data'
            } ]
        }
        
        const mockAdminJwks = {
            keys: [ { 
                kid: 'admin-key-1', 
                kty: 'RSA', 
                use: 'sig',
                n: 'admin-key-data'
            } ]
        }
        
        // Mock helper instances
        mockKeycloakClient = {
            getJwksForRoute: jest.fn( ( { route } ) => {
                if( route === '/api' ) {
                    return Promise.resolve( { jwksData: mockApiJwks } )
                } else if( route === '/admin' ) {
                    return Promise.resolve( { jwksData: mockAdminJwks } )
                }
                return Promise.resolve( { jwksData: { keys: [] } } )
            } ),
            getAllRoutes: jest.fn().mockReturnValue( [ '/api', '/admin' ] )
        }
        
        mockTokenValidator = {
            validateForRoute: jest.fn().mockResolvedValue( { isValid: true, decoded: {} } ),
            getAllRoutes: jest.fn().mockReturnValue( [ '/api', '/admin' ] )
        }
        
        mockOAuthFlowHandler = {
            initiateAuthorizationCodeFlowForRoute: jest.fn().mockReturnValue( {
                authorizationUrl: 'http://localhost:8080/auth',
                state: 'test-state',
                route: '/api'
            } ),
            getAllRoutes: jest.fn().mockReturnValue( [ '/api', '/admin' ] )
        }
        
        // Setup mock returns
        mockKeycloakClientForMultiRealm.mockResolvedValue( mockKeycloakClient )
        mockTokenValidatorForMultiRealm.mockReturnValue( mockTokenValidator )
        mockOAuthFlowHandlerForMultiRealm.mockReturnValue( mockOAuthFlowHandler )
        
        // Create middleware and Express app
        middleware = await OAuthMiddleware.create( {
            realmsByRoute: testRealmsByRoute,
            silent: true // Suppress console output during tests
        } )
        
        app = express()
        app.use( middleware.router() )
    } )

    afterEach( () => {
        // Restore original environment
        process.env.NODE_ENV = originalEnv
    } )


    describe( 'OAuth Authorization Server Metadata (RFC 8414)', () => {
        it( 'serves gateway authorization server metadata', async () => {
            // Set NODE_ENV to development to bypass HTTPS requirement for testing
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/.well-known/oauth-authorization-server' )
                .expect( 200 )
                .expect( 'Content-Type', /application\/json/ )
            
            expect( response.body ).toMatchObject( {
                // Gateway metadata
                issuer: expect.any( String ),
                
                // Multi-realm support
                authorization_servers: expect.any( Object ),
                realms_supported: expect.arrayContaining( [ 'http://localhost:8080/realms/api-realm', 'http://localhost:8080/realms/admin-realm' ] ),
                routes_supported: expect.arrayContaining( [ '/api', '/admin' ] ),
                
                // RFC 8414 required fields
                response_types_supported: expect.arrayContaining( [ 'code' ] ),
                grant_types_supported: expect.arrayContaining( [ 'authorization_code', 'client_credentials', 'refresh_token' ] ),
                token_endpoint_auth_methods_supported: expect.any( Array ),
                
                // RFC 8707 Resource Indicators support
                resource_indicators_supported: true,
                
                // OAuth 2.1 Security
                code_challenge_methods_supported: expect.arrayContaining( [ 'S256' ] ),
                
                // Route → Realm mapping
                route_realm_mapping: expect.objectContaining( {
                    '/api': expect.objectContaining( {
                        realm: 'api-realm',
                        issuer: 'http://localhost:8080/realms/api-realm'
                    } ),
                    '/admin': expect.objectContaining( {
                        realm: 'admin-realm',
                        issuer: 'http://localhost:8080/realms/admin-realm'
                    } )
                } ),
                
                // RFC compliance information
                rfc_compliance: expect.objectContaining( {
                    'rfc8414': 'OAuth 2.0 Authorization Server Metadata',
                    'rfc9728': 'OAuth 2.0 Protected Resource Metadata',
                    'rfc8707': 'OAuth 2.0 Resource Indicators'
                } )
            } )
            
            // Verify caching headers
            expect( response.headers['cache-control'] ).toBe( 'public, max-age=300' )
            expect( response.headers['access-control-allow-origin'] ).toBe( '*' )
        } )
    } )


    describe( 'Multi-Realm JWKS Aggregation', () => {
        it( 'aggregates JWKS from all realms', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/.well-known/jwks.json' )
                .expect( 200 )
                .expect( 'Content-Type', /application\/jwk-set\+json/ )
            
            expect( response.body ).toHaveProperty( 'keys' )
            expect( response.body.keys ).toHaveLength( 2 ) // One from each realm
            
            const keyIds = response.body.keys.map( key => key.kid )
            expect( keyIds ).toContain( 'api-key-1' )
            expect( keyIds ).toContain( 'admin-key-1' )
            
            // Verify JWKS caching headers
            expect( response.headers['cache-control'] ).toBe( 'public, max-age=300' )
        } )
    } )


    describe( 'Protected Resource Metadata (RFC 9728)', () => {
        it( 'serves route-specific protected resource metadata', async () => {
            process.env.NODE_ENV = 'development'
            
            const response = await request( app )
                .get( '/.well-known/oauth-protected-resource/api' )
                .expect( 200 )
                .expect( 'Content-Type', /application\/json/ )
            
            expect( response.body ).toMatchObject( {
                resource: expect.stringContaining( '/api' ), // Dynamic port in tests
                authorization_servers: [ 'http://localhost:8080/realms/api-realm' ],
                scopes_supported: [ 'api:read' ],
                bearer_methods_supported: [ 'header' ],
                resource_documentation: expect.any( String )
            } )
            
            // Verify RFC 9728 caching headers
            expect( response.headers['cache-control'] ).toBe( 'public, max-age=300' )
        } )
    } )
} )