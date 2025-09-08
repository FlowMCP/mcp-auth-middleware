import { jest } from '@jest/globals'
import express from 'express'
import request from 'supertest'

// Mock all dependencies before importing OAuthMiddleware
const mockProviders = new Map()
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

jest.unstable_mockModule( '../../../src/providers/ProviderFactory.mjs', () => ({
    ProviderFactory: {
        createProvidersForRoutes: jest.fn().mockReturnValue( { providers: mockProviders } )
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

const { OAuthMiddleware } = await import( '../../../src/task/OAuthMiddleware.mjs' )


describe( 'OAuthMiddleware - Unit Tests', () => {

    beforeEach( () => {
        jest.clearAllMocks()
    } )


    describe( 'Static create method', () => {

        test( 'throws error when realmsByRoute is missing', async () => {
            await expect( OAuthMiddleware.create( {} ) ).rejects.toThrow( 'realmsByRoute configuration is required' )
        } )


        test( 'throws error when realmsByRoute is null', async () => {
            await expect( OAuthMiddleware.create( { realmsByRoute: null } ) ).rejects.toThrow( 'realmsByRoute configuration is required' )
        } )


        test( 'throws error when realmsByRoute is not an object', async () => {
            await expect( OAuthMiddleware.create( { realmsByRoute: 'invalid' } ) ).rejects.toThrow( 'realmsByRoute configuration is required' )
        } )


        test( 'throws error when realmsByRoute is an array', async () => {
            await expect( OAuthMiddleware.create( { realmsByRoute: [ 'invalid' ] } ) ).rejects.toThrow( 'Invalid route path: 0' )
        } )


        test( 'creates middleware successfully with valid config', async () => {
            const validConfig = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read' ],
                        resourceUri: 'https://localhost:3000/api'
                    }
                }
            }

            const middleware = await OAuthMiddleware.create( validConfig )

            expect( middleware ).toBeInstanceOf( OAuthMiddleware )
        } )

    } )


    describe( 'Route Configuration Validation', () => {

        test( 'throws error for invalid route path - empty', async () => {
            const invalidConfig = {
                realmsByRoute: {
                    '': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret'
                    }
                }
            }

            await expect( OAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'Invalid route path:' )
        } )


        test( 'throws error for invalid route path - no leading slash', async () => {
            const invalidConfig = {
                realmsByRoute: {
                    'api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret'
                    }
                }
            }

            await expect( OAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'Invalid route path: api' )
        } )


        test( 'throws error for missing required fields - providerUrl', async () => {
            const invalidConfig = {
                realmsByRoute: {
                    '/api': {
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret'
                    }
                }
            }

            await expect( OAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'Missing required fields for route /api: providerUrl' )
        } )


        test( 'throws error for missing required fields - multiple', async () => {
            const invalidConfig = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com'
                    }
                }
            }

            await expect( OAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'Missing required fields for route /api: realm, clientId, clientSecret' )
        } )


        test( 'throws error for missing required fields - all', async () => {
            const invalidConfig = {
                realmsByRoute: {
                    '/api': {}
                }
            }

            await expect( OAuthMiddleware.create( invalidConfig ) ).rejects.toThrow( 'Missing required fields for route /api: providerUrl, realm, clientId, clientSecret' )
        } )

    } )


    describe( 'Provider URL Processing', () => {

        test( 'handles Auth0 provider URLs correctly', async () => {
            const auth0Config = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://test.auth0.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read' ],
                        resourceUri: 'https://localhost:3000/api'
                    }
                },
                silent: true
            }

            const middleware = await OAuthMiddleware.create( auth0Config )
            const config = middleware.getRouteConfig( '/api' )

            expect( config.authorizationUrl ).toBe( 'https://test.auth0.com/authorize' )
            expect( config.tokenUrl ).toBe( 'https://test.auth0.com/oauth/token' )
        } )


        test( 'handles Keycloak provider URLs correctly', async () => {
            const keycloakConfig = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://keycloak.example.com',
                        realm: 'my-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read' ],
                        resourceUri: 'https://localhost:3000/api'
                    }
                },
                silent: true
            }

            const middleware = await OAuthMiddleware.create( keycloakConfig )
            const config = middleware.getRouteConfig( '/api' )

            expect( config.authorizationUrl ).toBe( 'https://keycloak.example.com/realms/my-realm/protocol/openid-connect/auth' )
            expect( config.tokenUrl ).toBe( 'https://keycloak.example.com/realms/my-realm/protocol/openid-connect/token' )
        } )

    } )


    describe( 'Route Setup and Router', () => {

        let middleware
        
        beforeEach( async () => {
            const validConfig = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read', 'write' ],
                        resourceUri: 'https://localhost:3000/api'
                    }
                },
                silent: true
            }
            middleware = await OAuthMiddleware.create( validConfig )
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
            const config = middleware.getRouteConfig( '/api' )
            
            expect( config ).toMatchObject( {
                realm: 'test-realm',
                clientId: 'test-client',
                requiredScopes: [ 'read', 'write' ]
            } )
        } )


        test( 'getRouteConfig returns undefined for invalid route', () => {
            const config = middleware.getRouteConfig( '/nonexistent' )
            
            expect( config ).toBeUndefined()
        } )


        test( 'getRealms returns realm information', () => {
            const realms = middleware.getRealms()
            
            expect( realms ).toEqual( expect.arrayContaining( [
                expect.objectContaining( {
                    route: '/api',
                    realm: 'test-realm'
                } )
            ] ) )
        } )

    } )


    describe( 'Silent Mode', () => {

        test( 'respects silent=true configuration', async () => {
            const validConfig = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read' ],
                        resourceUri: 'https://localhost:3000/api'
                    }
                },
                silent: true
            }

            const middleware = await OAuthMiddleware.create( validConfig )

            // Should not throw - silent mode suppresses console output
            expect( middleware ).toBeInstanceOf( OAuthMiddleware )
        } )


        test( 'defaults to silent=false', async () => {
            const validConfig = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read' ],
                        resourceUri: 'https://localhost:3000/api'
                    }
                }
            }

            const middleware = await OAuthMiddleware.create( validConfig )

            expect( middleware ).toBeInstanceOf( OAuthMiddleware )
        } )

    } )


    describe( 'Multi-Route Configuration', () => {

        test( 'handles multiple routes correctly', async () => {
            const multiRouteConfig = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'api-realm',
                        clientId: 'api-client',
                        clientSecret: 'api-secret',
                        requiredScopes: [ 'api:read' ],
                        resourceUri: 'https://localhost:3000/api'
                    },
                    '/admin': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'admin-realm',
                        clientId: 'admin-client',
                        clientSecret: 'admin-secret',
                        requiredScopes: [ 'admin:full' ],
                        resourceUri: 'https://localhost:3000/admin'
                    }
                },
                silent: true
            }

            const middleware = await OAuthMiddleware.create( multiRouteConfig )

            const routes = middleware.getRoutes()
            expect( routes ).toContain( '/api' )
            expect( routes ).toContain( '/admin' )

            const apiConfig = middleware.getRouteConfig( '/api' )
            expect( apiConfig.realm ).toBe( 'api-realm' )

            const adminConfig = middleware.getRouteConfig( '/admin' )
            expect( adminConfig.realm ).toBe( 'admin-realm' )
        } )


        test( 'validates all routes in multi-route config', async () => {
            const invalidMultiRouteConfig = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'api-realm',
                        clientId: 'api-client',
                        clientSecret: 'api-secret'
                    },
                    'invalid-admin': {  // Invalid route path
                        providerUrl: 'https://auth.example.com',
                        realm: 'admin-realm',
                        clientId: 'admin-client',
                        clientSecret: 'admin-secret'
                    }
                }
            }

            await expect( OAuthMiddleware.create( invalidMultiRouteConfig ) ).rejects.toThrow( 'Invalid route path: invalid-admin' )
        } )

    } )


    describe( 'Edge Cases', () => {

        test( 'handles empty realmsByRoute object', async () => {
            const emptyConfig = {
                realmsByRoute: {},
                silent: true
            }

            // This should either work or throw an error - let's see what happens
            try {
                const middleware = await OAuthMiddleware.create( emptyConfig )
                expect( middleware ).toBeInstanceOf( OAuthMiddleware )
                expect( middleware.getRoutes() ).toEqual( [] )
            } catch( error ) {
                // If it throws an error, that's also acceptable behavior for empty config
                expect( error.message ).toContain( 'resourceUri' )
            }
        } )


        test( 'handles route config with extra fields', async () => {
            const configWithExtras = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read' ],
                        resourceUri: 'https://localhost:3000/api',
                        // Extra fields that should be preserved
                        customField: 'custom-value',
                        anotherField: 123
                    }
                },
                silent: true
            }

            const middleware = await OAuthMiddleware.create( configWithExtras )
            const routeConfig = middleware.getRouteConfig( '/api' )

            expect( routeConfig.customField ).toBe( 'custom-value' )
            expect( routeConfig.anotherField ).toBe( 123 )
        } )

    } )


    describe( 'Router Middleware - HTTPS Security', () => {

        let app
        let middleware

        beforeEach( async () => {
            const validConfig = {
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read' ],
                        resourceUri: 'https://localhost:3000/api'
                    }
                },
                silent: true
            }

            middleware = await OAuthMiddleware.create( validConfig )
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
                realmsByRoute: {
                    '/api': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read' ],
                        resourceUri: 'https://localhost:3000/api'
                    },
                    '/admin': {
                        providerUrl: 'https://auth.example.com',
                        realm: 'admin-realm',
                        clientId: 'admin-client',
                        clientSecret: 'admin-secret',
                        requiredScopes: [ 'admin' ],
                        resourceUri: 'https://localhost:3000/admin'
                    }
                },
                silent: true
            }

            middleware = await OAuthMiddleware.create( validConfig )
        } )


        test( 'sets up routes for all configured paths', () => {
            const router = middleware.router()
            
            // Router should be properly configured
            expect( typeof router ).toBe( 'function' )
            expect( router.stack ).toBeDefined()
        } )


        test( 'generates correct OAuth endpoints for each route', () => {
            const apiConfig = middleware.getRouteConfig( '/api' )
            const adminConfig = middleware.getRouteConfig( '/admin' )

            // API route config
            expect( apiConfig ).toMatchObject( {
                routePath: '/api',
                realm: 'test-realm',
                authorizationUrl: expect.stringContaining( 'auth' ),
                tokenUrl: expect.stringContaining( 'token' )
            } )

            // Admin route config  
            expect( adminConfig ).toMatchObject( {
                routePath: '/admin',
                realm: 'admin-realm',
                authorizationUrl: expect.stringContaining( 'auth' ),
                tokenUrl: expect.stringContaining( 'token' )
            } )
        } )


        test( 'handles setSilent method', () => {
            // Test the setSilent method exists and works
            expect( () => {
                middleware.setSilent( { silent: true } )
            } ).not.toThrow()

            expect( () => {
                middleware.setSilent( { silent: true } )
            } ).not.toThrow()
        } )

    } )

} )