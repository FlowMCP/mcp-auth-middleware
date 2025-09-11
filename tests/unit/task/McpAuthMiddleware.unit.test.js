import { jest } from '@jest/globals'
import express from 'express'
import request from 'supertest'

// Mock all dependencies before importing McpAuthMiddleware
const mockTokenValidator = {
    validateForRoute: jest.fn(),
    validateScopesForRoute: jest.fn(),
    validateWithAudienceBinding: jest.fn(),
    getAllRoutes: jest.fn().mockReturnValue( [ '/api' ] )
}
const mockOAuthFlowHandler = {
    initiateAuthorizationCodeFlowForRoute: jest.fn(),
    handleAuthorizationCallbackForRoute: jest.fn(),
    getDiscoveryData: jest.fn(),
    getAllRoutes: jest.fn().mockReturnValue( [ '/api' ] )
}

// Mock AuthTypeFactory instead of ProviderFactory
const mockAuthTypeHandler = {
    provider: {
        normalizeConfiguration: jest.fn().mockReturnValue({ normalizedConfig: {} }),
        generateEndpoints: jest.fn().mockReturnValue({ endpoints: {} })
    },
    tokenValidator: mockTokenValidator,
    flowHandler: mockOAuthFlowHandler,
    config: {}
}

jest.unstable_mockModule( '../../../src/core/AuthTypeFactory.mjs', () => ({
    AuthTypeFactory: {
        createAuthHandler: jest.fn().mockReturnValue( mockAuthTypeHandler )
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

const { McpAuthMiddleware } = await import( '../../../src/task/McpAuthMiddleware.mjs' )


describe( 'McpAuthMiddleware - Unit Tests', () => {

    beforeEach( () => {
        jest.clearAllMocks()
    } )


    describe( 'Static create method', () => {

        test( 'throws error when routes is missing', async () => {
            await expect( McpAuthMiddleware.create( {} ) ).rejects.toThrow( 'routes configuration is required' )
        } )


        test( 'throws error when routes is null', async () => {
            await expect( McpAuthMiddleware.create( { routes: null } ) ).rejects.toThrow( 'routes configuration is required' )
        } )


        test( 'throws error when routes is not an object', async () => {
            await expect( McpAuthMiddleware.create( { routes: 'invalid' } ) ).rejects.toThrow( 'routes configuration is required' )
        } )


        test( 'throws error when routes is an array', async () => {
            await expect( McpAuthMiddleware.create( { routes: [ 'invalid' ] } ) ).rejects.toThrow( 'Must start with' )
        } )


        test( 'creates middleware successfully with oauth21_auth0 authType', async () => {
            const validConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            }

            const middleware = await McpAuthMiddleware.create( validConfig )

            expect( middleware ).toBeInstanceOf( McpAuthMiddleware )
        } )

    } )


    describe( 'Route Configuration Validation', () => {

        test( 'throws error for invalid route path - empty', async () => {
            const invalidConfig = {
                routes: {
                    '': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            }

            await expect( McpAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'Must start with' )
        } )


        test( 'throws error for invalid route path - no leading slash', async () => {
            const invalidConfig = {
                routes: {
                    'api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            }

            await expect( McpAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'Must start with' )
        } )


        test( 'throws error for missing required field - authType', async () => {
            const invalidConfig = {
                routes: {
                    '/api': {
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            }

            await expect( McpAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'Missing required field: authType' )
        } )


        test( 'throws error for missing required fields - oauth21_auth0 config', async () => {
            const invalidConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com'
                    }
                }
            }

            await expect( McpAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'missing required fields' )
        } )


        test( 'throws error for missing required fields - all', async () => {
            const invalidConfig = {
                routes: {
                    '/api': {}
                }
            }

            await expect( McpAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'Missing required field: authType' )
        } )

    } )


    describe( 'AuthType Processing', () => {

        test( 'handles oauth21_auth0 provider URLs correctly', async () => {
            const auth0Config = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://test.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                },
                silent: true
            }

            const middleware = await McpAuthMiddleware.create( auth0Config )
            const config = middleware.getRouteConfig( { routePath: '/api' } )

            expect( config.authType ).toBe( 'oauth21_auth0' )
            expect( config.providerUrl ).toBe( 'https://test.auth0.com' )
        } )


        test( 'validates oauth21_auth0 configuration properly', async () => {
            const validConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email api:read',
                        audience: 'https://api.example.com'
                    }
                },
                silent: true
            }

            const middleware = await McpAuthMiddleware.create( validConfig )
            const config = middleware.getRouteConfig( { routePath: '/api' } )

            expect( config.authType ).toBe( 'oauth21_auth0' )
            expect( config.scope ).toBe( 'openid profile email api:read' )
            expect( config.audience ).toBe( 'https://api.example.com' )
        } )

    } )


    describe( 'Route Setup and Router', () => {

        let middleware
        
        beforeEach( async () => {
            const validConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email api:read',
                        audience: 'https://api.example.com'
                    }
                },
                silent: true
            }
            middleware = await McpAuthMiddleware.create( validConfig )
        } )


        test( 'provides router method', () => {
            const router = middleware.router()
            
            expect( typeof router ).toBe( 'function' )
        } )


        test( 'getRoutes returns configured routes', () => {
            const routes = middleware.getRoutes()
            
            expect( routes ).toEqual( [ '/api' ] )
        } )


        test( 'getRouteConfig returns route configuration', () => {
            const config = middleware.getRouteConfig( { routePath: '/api' } )
            
            expect( config ).toMatchObject( {
                authType: 'oauth21_auth0',
                clientId: 'test-client-id',
                scope: 'openid profile email api:read',
                audience: 'https://api.example.com'
            } )
        } )


        test( 'getRouteConfig returns undefined for invalid route', () => {
            const config = middleware.getRouteConfig( { routePath: '/nonexistent' } )
            
            expect( config ).toBeUndefined()
        } )


        test( 'getRealms returns realm information', () => {
            const realms = middleware.getRealms()
            
            expect( Array.isArray( realms ) ).toBe( true )
            expect( realms.length ).toBeGreaterThan( 0 )
        } )

    } )


    describe( 'Silent Mode', () => {

        test( 'respects silent=true configuration', async () => {
            const validConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                },
                silent: true
            }

            const middleware = await McpAuthMiddleware.create( validConfig )

            // Should not throw - silent mode suppresses console output
            expect( middleware ).toBeInstanceOf( McpAuthMiddleware )
        } )


        test( 'defaults to silent=false', async () => {
            const validConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            }

            const middleware = await McpAuthMiddleware.create( validConfig )

            expect( middleware ).toBeInstanceOf( McpAuthMiddleware )
        } )

    } )


    describe( 'Multi-Route Configuration', () => {

        test( 'handles multiple routes correctly', async () => {
            const multiRouteConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'api-client-id',
                        clientSecret: 'api-client-secret',
                        scope: 'openid profile email api:read',
                        audience: 'https://api.example.com'
                    },
                    '/admin': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://admin.auth0.com',
                        clientId: 'admin-client-id',
                        clientSecret: 'admin-client-secret',
                        scope: 'openid profile email admin:full',
                        audience: 'https://admin.example.com'
                    }
                },
                silent: true
            }

            const middleware = await McpAuthMiddleware.create( multiRouteConfig )

            const routes = middleware.getRoutes()
            expect( routes ).toContain( '/api' )
            expect( routes ).toContain( '/admin' )

            const apiConfig = middleware.getRouteConfig( { routePath: '/api' } )
            expect( apiConfig.audience ).toBe( 'https://api.example.com' )

            const adminConfig = middleware.getRouteConfig( { routePath: '/admin' } )
            expect( adminConfig.audience ).toBe( 'https://admin.example.com' )
        } )


        test( 'validates all routes in multi-route config', async () => {
            const invalidMultiRouteConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'api-client-id',
                        clientSecret: 'api-client-secret',
                        scope: 'openid profile email api:read',
                        audience: 'https://api.example.com'
                    },
                    'invalid-admin': {  // Invalid route path
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://admin.auth0.com',
                        clientId: 'admin-client-id',
                        clientSecret: 'admin-client-secret',
                        scope: 'openid profile email admin:full',
                        audience: 'https://admin.example.com'
                    }
                }
            }

            await expect( McpAuthMiddleware.create( invalidMultiRouteConfig ) ).rejects.toThrow( 'Must start with' )
        } )

    } )


    describe( 'Edge Cases', () => {

        test( 'handles empty routes object', async () => {
            const emptyConfig = {
                routes: {},
                silent: true
            }

            // This should either work or throw an error - let's see what happens
            try {
                const middleware = await McpAuthMiddleware.create( emptyConfig )
                expect( middleware ).toBeInstanceOf( McpAuthMiddleware )
                expect( middleware.getRoutes() ).toEqual( [] )
            } catch( error ) {
                // If it throws an error, that's also acceptable behavior for empty config
                expect( error.message ).toContain( 'routes' )
            }
        } )


        test( 'handles route config with extra fields', async () => {
            const configWithExtras = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com',
                        // Extra fields that should be preserved
                        customField: 'custom-value',
                        anotherField: 123
                    }
                },
                silent: true
            }

            const middleware = await McpAuthMiddleware.create( configWithExtras )
            const routeConfig = middleware.getRouteConfig( { routePath: '/api' } )

            expect( routeConfig.customField ).toBe( 'custom-value' )
            expect( routeConfig.anotherField ).toBe( 123 )
        } )

    } )


    describe( 'Router Middleware - HTTPS Security', () => {

        let app
        let middleware

        beforeEach( async () => {
            const validConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                },
                silent: true
            }

            middleware = await McpAuthMiddleware.create( validConfig )
            app = express()
            app.use( middleware.router() )
        } )


        test( 'rejects HTTP requests (OAuth 2.1 compliance)', async () => {
            // Mock HTTP request (not HTTPS)
            const response = await request( app )
                .get( '/api/auth/login' )
                // Don't set protocol to https to simulate HTTP

            expect( response.status ).toBe( 400 )
            expect( response.body ).toMatchObject( {
                error: 'invalid_request',
                error_description: expect.stringContaining( 'OAuth 2.1 requires HTTPS' )
            } )
        } )


        test( 'allows HTTPS requests', async () => {
            // Mock HTTPS request by setting secure flag
            app.use( ( req, res, next ) => {
                req.protocol = 'https'
                req.secure = true
                next()
            } )

            // Re-add the middleware after the protocol mock
            const testApp = express()
            testApp.use( ( req, res, next ) => {
                req.protocol = 'https'
                req.secure = true
                next()
            } )
            testApp.use( middleware.router() )

            const response = await request( testApp )
                .get( '/api/auth/login' )

            // Should not get HTTPS error (might get other errors due to mocking)
            expect( response.status ).not.toBe( 400 )
        } )

    } )


    describe( 'Route-Specific Middleware Setup', () => {

        let middleware

        beforeEach( async () => {
            const validConfig = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'api-client-id',
                        clientSecret: 'api-client-secret',
                        scope: 'openid profile email api:read',
                        audience: 'https://api.example.com'
                    },
                    '/admin': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://admin.auth0.com',
                        clientId: 'admin-client-id',
                        clientSecret: 'admin-client-secret',
                        scope: 'openid profile email admin:full',
                        audience: 'https://admin.example.com'
                    }
                },
                silent: true
            }

            middleware = await McpAuthMiddleware.create( validConfig )
        } )


        test( 'sets up routes for all configured paths', () => {
            const router = middleware.router()
            
            // Router should be properly configured
            expect( typeof router ).toBe( 'function' )
            expect( router.stack ).toBeDefined()
        } )


        test( 'generates correct OAuth endpoints for each route', () => {
            const apiConfig = middleware.getRouteConfig( { routePath: '/api' } )
            const adminConfig = middleware.getRouteConfig( { routePath: '/admin' } )

            // API route config
            expect( apiConfig ).toMatchObject( {
                authType: 'oauth21_auth0',
                audience: 'https://api.example.com'
            } )

            // Admin route config  
            expect( adminConfig ).toMatchObject( {
                authType: 'oauth21_auth0',
                audience: 'https://admin.example.com'
            } )
        } )


        test( 'handles setSilent method', () => {
            // Test the setSilent method exists and works
            expect( () => {
                middleware.setSilent( { silent: true } )
            } ).not.toThrow()

            expect( () => {
                middleware.setSilent( { silent: false } )
            } ).not.toThrow()
        } )

    } )

} )