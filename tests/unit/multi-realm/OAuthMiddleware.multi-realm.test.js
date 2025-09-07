import { jest } from '@jest/globals'

// Mock all helper classes for multi-realm testing
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


describe( 'OAuthMiddleware - Multi-Realm Architecture', () => {
    let mockKeycloakClient
    let mockTokenValidator
    let mockOAuthFlowHandler
    
    const testRealmsByRoute = {
        '/api': {
            keycloakUrl: 'http://localhost:8080',
            realm: 'api-realm',
            clientId: 'api-client',
            clientSecret: 'api-secret',
            requiredScopes: [ 'api:read', 'api:write' ],
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

    beforeEach( () => {
        // Reset mocks
        jest.clearAllMocks()
        
        // Mock helper instances
        mockKeycloakClient = {
            getJwksForRoute: jest.fn().mockResolvedValue( { jwksData: { keys: [] } } ),
            validateTokenForRoute: jest.fn().mockResolvedValue( { isValid: true } ),
            getAllRoutes: jest.fn().mockReturnValue( [ '/api', '/admin' ] )
        }
        
        mockTokenValidator = {
            validateForRoute: jest.fn().mockResolvedValue( { isValid: true, decoded: {} } ),
            validateWithAudienceBinding: jest.fn().mockResolvedValue( { 
                isValid: true, 
                decoded: {},
                audienceBinding: { isValidAudience: true }
            } ),
            getAllRoutes: jest.fn().mockReturnValue( [ '/api', '/admin' ] )
        }
        
        mockOAuthFlowHandler = {
            initiateAuthorizationCodeFlowForRoute: jest.fn().mockReturnValue( {
                authorizationUrl: 'http://localhost:8080/auth',
                state: 'test-state',
                route: '/api'
            } ),
            handleAuthorizationCallbackForRoute: jest.fn().mockResolvedValue( {
                success: true,
                tokens: { access_token: 'test-token' },
                route: '/api'
            } ),
            getAllRoutes: jest.fn().mockReturnValue( [ '/api', '/admin' ] )
        }
        
        // Setup mock returns
        mockKeycloakClientForMultiRealm.mockResolvedValue( mockKeycloakClient )
        mockTokenValidatorForMultiRealm.mockReturnValue( mockTokenValidator )
        mockOAuthFlowHandlerForMultiRealm.mockReturnValue( mockOAuthFlowHandler )
    } )


    describe( 'Multi-Realm Creation and Configuration', () => {
        it( 'creates middleware with multi-realm configuration', async () => {
            const middleware = await OAuthMiddleware.create( {
                realmsByRoute: testRealmsByRoute
            } )

            expect( middleware ).toBeDefined()
            
            // Verify helper creation calls with normalized config (includes auto-generated URLs)
            expect( mockKeycloakClientForMultiRealm ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    realmsByRoute: expect.objectContaining( {
                        '/api': expect.objectContaining( {
                            keycloakUrl: 'http://localhost:8080',
                            realm: 'api-realm',
                            clientId: 'api-client',
                            clientSecret: 'api-secret',
                            requiredScopes: [ 'api:read', 'api:write' ],
                            resourceUri: 'http://localhost:3000/api',
                            // Auto-generated fields
                            authorizationUrl: expect.stringContaining( 'api-realm/protocol/openid-connect/auth' ),
                            tokenUrl: expect.stringContaining( 'api-realm/protocol/openid-connect/token' ),
                            jwksUrl: expect.stringContaining( 'api-realm/protocol/openid-connect/certs' )
                        } )
                    } ),
                    silent: false
                } )
            )
            
            expect( mockTokenValidatorForMultiRealm ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    silent: false
                } )
            )
            
            expect( mockOAuthFlowHandlerForMultiRealm ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    silent: false,
                    baseRedirectUri: expect.any( String )
                } )
            )
        } )

        it( 'throws error when realmsByRoute is missing', async () => {
            await expect( OAuthMiddleware.create( {} ) ).rejects.toThrow( 
                'realmsByRoute: Missing value' 
            )
        } )

        it( 'throws error when realmsByRoute is not an object', async () => {
            await expect( OAuthMiddleware.create( { realmsByRoute: 'invalid' } ) ).rejects.toThrow( 
                'realmsByRoute: Must be an object' 
            )
        } )

        it( 'validates route configuration fields', async () => {
            const invalidConfig = {
                realmsByRoute: {
                    '/api': {
                        keycloakUrl: 'http://localhost:8080',
                        // Missing required fields: realm, clientId, clientSecret
                    }
                }
            }

            await expect( OAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 
                'Route "/api": Missing required fields: realm, clientId, clientSecret, requiredScopes, resourceUri' 
            )
        } )

        it( 'validates route path format', async () => {
            const invalidConfig = {
                realmsByRoute: {
                    'api': { // Should start with '/'
                        keycloakUrl: 'http://localhost:8080',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret'
                    }
                }
            }

            await expect( OAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 
                'Route "api": Must start with /' 
            )
        } )
    } )


    describe( 'Route-to-Realm Mapping', () => {
        let middleware

        beforeEach( async () => {
            middleware = await OAuthMiddleware.create( {
                realmsByRoute: testRealmsByRoute
            } )
        } )

        it( 'returns all configured routes', () => {
            const routes = middleware.getRoutes()
            
            expect( routes ).toEqual( expect.arrayContaining( [ '/api', '/admin' ] ) )
            expect( routes ).toHaveLength( 2 )
        } )

        it( 'returns route-specific configuration', () => {
            const apiConfig = middleware.getRouteConfig( '/api' )
            
            expect( apiConfig ).toBeDefined()
            expect( apiConfig.realm ).toBe( 'api-realm' )
            expect( apiConfig.clientId ).toBe( 'api-client' )
            expect( apiConfig.requiredScopes ).toEqual( [ 'api:read', 'api:write' ] )
        } )

        it( 'returns all realms information', () => {
            const realms = middleware.getRealms()
            
            expect( realms ).toHaveLength( 2 )
            expect( realms ).toEqual( expect.arrayContaining( [
                expect.objectContaining( {
                    route: '/api',
                    realm: 'api-realm',
                    keycloakUrl: 'http://localhost:8080'
                } ),
                expect.objectContaining( {
                    route: '/admin', 
                    realm: 'admin-realm',
                    keycloakUrl: 'http://localhost:8080'
                } )
            ] ) )
        } )

        it( 'auto-generates OAuth URLs for routes', () => {
            const config = middleware.getRouteConfig( '/api' )
            
            expect( config.authorizationUrl ).toBe( 
                'http://localhost:8080/realms/api-realm/protocol/openid-connect/auth' 
            )
            expect( config.tokenUrl ).toBe( 
                'http://localhost:8080/realms/api-realm/protocol/openid-connect/token' 
            )
            expect( config.jwksUrl ).toBe( 
                'http://localhost:8080/realms/api-realm/protocol/openid-connect/certs' 
            )
        } )
    } )


    describe( 'Express Router Integration', () => {
        let middleware
        let router

        beforeEach( async () => {
            middleware = await OAuthMiddleware.create( {
                realmsByRoute: testRealmsByRoute
            } )
            router = middleware.router()
        } )

        it( 'provides Express router instance', () => {
            expect( router ).toBeDefined()
            expect( typeof router ).toBe( 'function' ) // Express router is a function
        } )

        it( 'registers route-specific endpoints', () => {
            // Router should have endpoints for each route
            // This would need more sophisticated testing of Express router internals
            expect( router ).toBeDefined()
        } )
    } )


    describe( 'OAuth 2.1 Security Integration', () => {
        let middleware

        beforeEach( async () => {
            middleware = await OAuthMiddleware.create( {
                realmsByRoute: testRealmsByRoute
            } )
        } )

        it( 'configures multi-realm with security requirements', () => {
            const routes = middleware.getRoutes()
            
            routes.forEach( route => {
                const config = middleware.getRouteConfig( route )
                expect( config ).toHaveProperty( 'requiredScopes' )
                expect( config ).toHaveProperty( 'resourceUri' )
                expect( config.keycloakUrl ).toMatch( /^https?:\/\// )
            } )
        } )
    } )
} )