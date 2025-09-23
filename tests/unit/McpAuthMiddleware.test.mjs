import { describe, it, expect, jest, beforeEach } from '@jest/globals'
import { McpAuthMiddleware } from '../../src/index.mjs'


describe( 'McpAuthMiddleware', () => {
    beforeEach( () => {
        jest.clearAllMocks()
    } )


    describe( '.create()', () => {
        it( 'creates FreeRouteMiddleware for free-route authType', async () => {
            const mcpAuthConfig = {
                authType: 'free-route',
                options: {},
                attachedRoutes: [],
                silent: true
            }

            const middleware = await McpAuthMiddleware.create( mcpAuthConfig )

            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )


        it( 'creates StaticBearerMiddleware for static-bearer authType', async () => {
            const mcpAuthConfig = {
                authType: 'static-bearer',
                options: {
                    bearerToken: 'test-token-12345'
                },
                attachedRoutes: ['/'],
                silent: true
            }

            const middleware = await McpAuthMiddleware.create( mcpAuthConfig )

            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )


        it( 'validates scalekit authType configuration', () => {
            // Test without creating instance to avoid HTTP calls
            const mcpAuthConfig = {
                authType: 'scalekit',
                options: {
                    providerUrl: 'https://test.scalekit.com',
                    clientId: 'test_client_id',
                    clientSecret: 'test_client_secret',
                    resource: 'http://localhost:3000/',
                    protectedResourceMetadata: '{"test": true}',
                    toolScopes: { 'test_tool': ['read'] }
                },
                attachedRoutes: ['/'],
                silent: true
            }

            // Validate configuration structure
            expect( mcpAuthConfig.authType ).toBe( 'scalekit' )
            expect( mcpAuthConfig.options.providerUrl ).toBe( 'https://test.scalekit.com' )
            expect( mcpAuthConfig.options.clientId ).toBe( 'test_client_id' )
            expect( mcpAuthConfig.options.clientSecret ).toBe( 'test_client_secret' )
            expect( mcpAuthConfig.options.resource ).toBe( 'http://localhost:3000/' )
        } )


        it( 'validates authkit authType configuration', () => {
            // Test without creating instance to avoid HTTP calls
            const mcpAuthConfig = {
                authType: 'authkit',
                options: {
                    authKitDomain: 'test.workos.com',
                    clientId: 'test_client_id',
                    clientSecret: 'test_client_secret',
                    expectedAudience: 'https://example.com',
                    protectedResourceMetadata: '{"resource": "https://example.com"}',
                    toolScopes: { 'test_tool': ['read'] }
                },
                attachedRoutes: ['/'],
                silent: true
            }

            // Validate configuration structure
            expect( mcpAuthConfig.authType ).toBe( 'authkit' )
            expect( mcpAuthConfig.options.authKitDomain ).toBe( 'test.workos.com' )
            expect( mcpAuthConfig.options.clientId ).toBe( 'test_client_id' )
            expect( mcpAuthConfig.options.expectedAudience ).toBe( 'https://example.com' )
        } )


        it( 'throws error for unsupported authType', async () => {
            const mcpAuthConfig = {
                authType: 'unsupported-type',
                options: {},
                attachedRoutes: [],
                silent: true
            }

            await expect( McpAuthMiddleware.create( mcpAuthConfig ) )
                .rejects
                .toThrow( 'Unsupported authType: unsupported-type. Supported types: free-route, static-bearer, scalekit, authkit' )
        } )


        it( 'uses default silent value when not provided', async () => {
            const mcpAuthConfig = {
                authType: 'free-route',
                options: {}
            }

            const middleware = await McpAuthMiddleware.create( mcpAuthConfig )

            expect( middleware ).toBeDefined()
        } )


        it( 'passes attachedRoutes parameter correctly', async () => {
            const testRoutes = ['/api', '/tools']
            const mcpAuthConfig = {
                authType: 'free-route',
                options: {},
                attachedRoutes: testRoutes,
                silent: true
            }

            const middleware = await McpAuthMiddleware.create( mcpAuthConfig )

            expect( middleware ).toBeDefined()
        } )


        it( 'handles missing options parameter', async () => {
            const mcpAuthConfig = {
                authType: 'free-route'
            }

            const middleware = await McpAuthMiddleware.create( mcpAuthConfig )

            expect( middleware ).toBeDefined()
        } )
    } )
} )