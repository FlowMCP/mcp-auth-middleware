import { jest } from '@jest/globals'

// Mock all helper classes for multi-realm testing
const mockAuthTypeHandlerForMultiRealm = jest.fn()
const mockTokenValidatorForMultiRealm = jest.fn()
const mockOAuthFlowHandlerForMultiRealm = jest.fn()

jest.unstable_mockModule( '../../../src/core/AuthTypeFactory.mjs', () => ({
    AuthTypeFactory: {
        createAuthHandler: mockAuthTypeHandlerForMultiRealm
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

const { McpAuthMiddleware } = await import( '../../../src/index.mjs' )

// Test configuration using authType system
const config = {
    providerUrl: 'https://tenant.auth0.com',
    clientIdBase: 'test-client',
    clientSecretBase: 'test-secret',
    silent: true
}

describe( 'McpAuthMiddleware - Multi-Realm Architecture', () => {
    let mockAuthTypeHandler
    let mockTokenValidator
    let mockOAuthFlowHandler
    
    const testRealmsByRoute = {
        '/api': {
            authType: 'oauth21_auth0',
            providerUrl: config.providerUrl,
            clientId: 'api-client-id',
            clientSecret: 'api-client-secret',
            scope: 'openid profile email api:read api:write',
            audience: 'https://api.example.com'
        },
        '/admin': {
            authType: 'oauth21_auth0',
            providerUrl: config.providerUrl,
            clientId: 'admin-client-id',
            clientSecret: 'admin-client-secret',
            scope: 'openid profile email admin:full',
            audience: 'https://admin.example.com'
        }
    }

    beforeEach( () => {
        // Reset mocks
        jest.clearAllMocks()
        
        // Mock AuthType handler instances  
        mockAuthTypeHandler = {
            provider: {
                normalizeConfiguration: jest.fn().mockReturnValue({ normalizedConfig: {} }),
                generateEndpoints: jest.fn().mockReturnValue({ endpoints: { 
                    jwksUrl: 'https://tenant.auth0.com/.well-known/jwks.json' 
                } })
            },
            tokenValidator: {
                validateToken: jest.fn().mockResolvedValue({ isValid: true, decoded: {} })
            },
            flowHandler: {
                initiateAuthFlow: jest.fn().mockReturnValue({
                    authorizationUrl: 'https://tenant.auth0.com/authorize',
                    state: 'test-state'
                }),
                handleCallback: jest.fn().mockResolvedValue({
                    success: true,
                    tokens: { access_token: 'test-token' }
                })
            },
            config: {}
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
                authorizationUrl: 'https://tenant.auth0.com/authorize',
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
        mockAuthTypeHandlerForMultiRealm.mockReturnValue( mockAuthTypeHandler )
        mockTokenValidatorForMultiRealm.mockReturnValue( mockTokenValidator )
        mockOAuthFlowHandlerForMultiRealm.mockReturnValue( mockOAuthFlowHandler )
    } )


    describe( 'Multi-Realm Creation and Configuration', () => {
        it( 'creates middleware with multi-realm configuration', async () => {
            const middleware = await McpAuthMiddleware.create( {
                routes: testRealmsByRoute,
                silent: true
            } )

            expect( middleware ).toBeDefined()
            
            // Verify AuthTypeFactory creation calls with normalized config
            expect( mockAuthTypeHandlerForMultiRealm ).toHaveBeenCalledWith( 
                expect.objectContaining( {
                    authType: 'oauth21_auth0',
                    config: expect.objectContaining( {
                        authType: 'oauth21_auth0',
                        providerUrl: config.providerUrl,
                        clientId: expect.any( String ),
                        clientSecret: expect.any( String ),
                        scope: expect.stringContaining( 'openid' ),
                        audience: expect.stringContaining( 'https://' )
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
                    silent: true
                } )
            )
        } )

        it( 'throws error when routes is missing', async () => {
            await expect( McpAuthMiddleware.create( {} ) ).rejects.toThrow( 
                'routes: Missing value' 
            )
        } )

        it( 'throws error when routes is not an object', async () => {
            await expect( McpAuthMiddleware.create( { routes: 'invalid' } ) ).rejects.toThrow( 
                'routes: Must be an object' 
            )
        } )

        it( 'validates route configuration fields', async () => {
            const invalidConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: config.providerUrl
                        // Missing required fields: clientId, clientSecret, scope, audience
                    }
                }
            }

            await expect( McpAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 
                'OAuth21 Auth0 configuration missing required fields'  // Should contain field validation errors
            )
        } )

        it( 'validates route path format', async () => {
            const invalidConfig = {
                routes: {
                    'api': { // Should start with '/'
                        authType: 'oauth21_auth0',
                        providerUrl: config.providerUrl,
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            }

            await expect( McpAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 
                'Must start with /' 
            )
        } )
    } )


    describe( 'Route-to-Realm Mapping', () => {
        let middleware

        beforeEach( async () => {
            middleware = await McpAuthMiddleware.create( {
                routes: testRealmsByRoute,
                silent: true
            } )
        } )

        it( 'returns all configured routes', () => {
            const routes = middleware.getRoutes()
            
            expect( routes ).toEqual( expect.arrayContaining( [ '/api', '/admin' ] ) )
            expect( routes ).toHaveLength( 2 )
        } )

        it( 'returns route-specific configuration', () => {
            const apiConfig = middleware.getRouteConfig( { routePath: '/api' } )
            
            expect( apiConfig ).toBeDefined()
            expect( apiConfig.authType ).toBe( 'oauth21_auth0' )
            expect( apiConfig.clientId ).toBe( 'api-client-id' )
            expect( apiConfig.scope ).toContain( 'api:read' )
            expect( apiConfig.audience ).toBe( 'https://api.example.com' )
        } )

        it( 'returns all realms information', () => {
            const realms = middleware.getRealms()
            
            expect( Array.isArray( realms ) ).toBe( true )
            expect( realms.length ).toBeGreaterThan( 0 )
        } )

        it( 'auto-generates OAuth URLs for routes', () => {
            const routeConfig = middleware.getRouteConfig( { routePath: '/api' } )
            
            expect( routeConfig.authType ).toBe( 'oauth21_auth0' )
            expect( routeConfig.providerUrl ).toBe( config.providerUrl )
            expect( routeConfig.audience ).toBe( 'https://api.example.com' )
        } )
    } )


    describe( 'Express Router Integration', () => {
        let middleware
        let router

        beforeEach( async () => {
            middleware = await McpAuthMiddleware.create( {
                routes: testRealmsByRoute,
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
            middleware = await McpAuthMiddleware.create( {
                routes: testRealmsByRoute,
                silent: true
            } )
        } )

        it( 'configures multi-realm with security requirements', () => {
            const routes = middleware.getRoutes()
            
            routes.forEach( route => {
                const config = middleware.getRouteConfig( { routePath: route } )
                expect( config ).toHaveProperty( 'authType' )
                expect( config ).toHaveProperty( 'scope' )
                expect( config ).toHaveProperty( 'audience' )
                expect( config.providerUrl ).toMatch( /^https?:\/\// )
            } )
        } )
    } )
} )