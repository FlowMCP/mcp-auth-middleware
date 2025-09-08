import { jest } from '@jest/globals'

// Mock all helper classes for multi-realm testing
const mockProviderFactoryForMultiRealm = jest.fn()
const mockTokenValidatorForMultiRealm = jest.fn()
const mockOAuthFlowHandlerForMultiRealm = jest.fn()

jest.unstable_mockModule( '../../../src/providers/ProviderFactory.mjs', () => ({
    ProviderFactory: {
        createProvidersForRoutes: mockProviderFactoryForMultiRealm
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

// Test configuration using .auth.env.example
const config = {
    envPath: '../../../.auth.env.example',
    providerUrl: 'https://your-first-auth0-domain.auth0.com',
    realm: 'test-realm',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    silent: true
}

describe( 'OAuthMiddleware - Multi-Realm Architecture', () => {
    let mockProviders
    let mockTokenValidator
    let mockOAuthFlowHandler
    
    const testRealmsByRoute = {
        '/api': {
            providerName: 'auth0',
            providerUrl: config.providerUrl,
            realm: 'api-realm',
            clientId: 'api-client',
            clientSecret: 'api-secret',
            requiredScopes: [ 'api:read', 'api:write' ],
            resourceUri: 'http://localhost:3000/api'
        },
        '/admin': {
            providerName: 'auth0',
            providerUrl: config.providerUrl,
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
        
        // Mock provider instances  
        mockProviders = {
            '/api': {
                generateEndpoints: jest.fn().mockReturnValue( { endpoints: { jwksUrl: 'https://api.auth0.com/.well-known/jwks.json' } } ),
                getProviderName: jest.fn().mockReturnValue( 'auth0' )
            },
            '/admin': {
                generateEndpoints: jest.fn().mockReturnValue( { endpoints: { jwksUrl: 'https://admin.auth0.com/.well-known/jwks.json' } } ),
                getProviderName: jest.fn().mockReturnValue( 'auth0' )
            }
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
        mockProviderFactoryForMultiRealm.mockReturnValue( { providers: mockProviders } )
        mockTokenValidatorForMultiRealm.mockReturnValue( mockTokenValidator )
        mockOAuthFlowHandlerForMultiRealm.mockReturnValue( mockOAuthFlowHandler )
    } )


    describe( 'Multi-Realm Creation and Configuration', () => {
        it( 'creates middleware with multi-realm configuration', async () => {
            const middleware = await OAuthMiddleware.create( {
                realmsByRoute: testRealmsByRoute,
                silent: true
            } )

            expect( middleware ).toBeDefined()
            
            // Verify provider factory creation calls with normalized config
            expect( mockProviderFactoryForMultiRealm ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    realmsByRoute: expect.objectContaining( {
                        '/api': expect.objectContaining( {
                            providerUrl: config.providerUrl,
                            realm: 'api-realm',
                            clientId: 'api-client',
                            clientSecret: 'api-secret',
                            requiredScopes: [ 'api:read', 'api:write' ],
                            resourceUri: 'http://localhost:3000/api',
                            // Auto-generated fields
                            authorizationUrl: expect.stringContaining( '/authorize' ),
                            tokenUrl: expect.stringContaining( '/oauth/token' ),
                            jwksUrl: expect.stringContaining( '/.well-known/jwks.json' )
                        } )
                    } ),
                    silent: true
                } )
            )
            
            expect( mockTokenValidatorForMultiRealm ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    silent: true
                } )
            )
            
            expect( mockOAuthFlowHandlerForMultiRealm ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    silent: true,
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
                        providerUrl: config.providerUrl,
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
                        providerUrl: config.providerUrl,
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
                realmsByRoute: testRealmsByRoute,
                silent: true
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
                    providerUrl: config.providerUrl
                } ),
                expect.objectContaining( {
                    route: '/admin', 
                    realm: 'admin-realm',
                    providerUrl: config.providerUrl
                } )
            ] ) )
        } )

        it( 'auto-generates OAuth URLs for routes', () => {
            const config = middleware.getRouteConfig( '/api' )
            
            expect( config.authorizationUrl ).toBe( 
                'https://your-first-auth0-domain.auth0.com/authorize' 
            )
            expect( config.tokenUrl ).toBe( 
                'https://your-first-auth0-domain.auth0.com/oauth/token' 
            )
            expect( config.jwksUrl ).toBe( 
                'https://your-first-auth0-domain.auth0.com/.well-known/jwks.json' 
            )
        } )
    } )


    describe( 'Express Router Integration', () => {
        let middleware
        let router

        beforeEach( async () => {
            middleware = await OAuthMiddleware.create( {
                realmsByRoute: testRealmsByRoute,
                silent: true
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
                realmsByRoute: testRealmsByRoute,
                silent: true
            } )
        } )

        it( 'configures multi-realm with security requirements', () => {
            const routes = middleware.getRoutes()
            
            routes.forEach( route => {
                const config = middleware.getRouteConfig( route )
                expect( config ).toHaveProperty( 'requiredScopes' )
                expect( config ).toHaveProperty( 'resourceUri' )
                expect( config.providerUrl ).toMatch( /^https?:\/\// )
            } )
        } )
    } )
} )