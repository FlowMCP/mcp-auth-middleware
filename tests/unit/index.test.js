import { jest } from '@jest/globals'

// Mock the McpAuthMiddleware implementation
const mockMcpAuthMiddlewareImpl = {
    router: jest.fn(),
    getRouteConfig: jest.fn(),
    getRouteClient: jest.fn(),
    getRoutes: jest.fn(),
    // getRealms method removed - routes handled via getRoutes/getRouteConfig
}

// Mock the Validation module
const mockValidation = {
    validationCreate: jest.fn(),
    validationGetRouteConfig: jest.fn()
}

jest.unstable_mockModule( '../../src/task/McpAuthMiddleware.mjs', () => ({
    McpAuthMiddleware: {
        create: jest.fn().mockResolvedValue( mockMcpAuthMiddlewareImpl )
    }
}) )

jest.unstable_mockModule( '../../src/task/Validation.mjs', () => ({
    Validation: mockValidation
}) )

const { McpAuthMiddleware } = await import( '../../src/index.mjs' )


describe( 'McpAuthMiddleware - Index Wrapper', () => {

    beforeEach( () => {
        jest.clearAllMocks()
    } )


    describe( 'create', () => {

        test( 'creates middleware successfully with staticBearer config', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )

            const middleware = await McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                }
            } )

            expect( middleware ).toBeDefined()
            expect( mockValidation.validationCreate ).toHaveBeenCalled()
        } )


        test( 'creates middleware successfully with oauth21 config', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )

            const middleware = await McpAuthMiddleware.create( {
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com',
                        mcpId: 'res_test123',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        resource: 'mcp:tools:*',
                        scope: 'mcp:tools:* mcp:resources:read'
                    }
                }
            } )

            expect( middleware ).toBeDefined()
            expect( mockValidation.validationCreate ).toHaveBeenCalled()
        } )


        test( 'creates middleware successfully with mixed config and silent parameter', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )

            const middleware = await McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com',
                        mcpId: 'res_test123',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        resource: 'mcp:tools:*',
                        scope: 'mcp:tools:* mcp:resources:read'
                    }
                },
                silent: true
            } )

            expect( middleware ).toBeDefined()
            expect( mockValidation.validationCreate ).toHaveBeenCalledWith( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com',
                        mcpId: 'res_test123',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        resource: 'mcp:tools:*',
                        scope: 'mcp:tools:* mcp:resources:read'
                    }
                },
                silent: true,
                baseUrl: 'http://localhost:3000',
                forceHttps: false
            } )
        } )


        test( 'throws error when validation fails', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: false,
                messages: [ 'Invalid configuration', 'Missing required field' ]
            } )

            await expect( McpAuthMiddleware.create( {
                staticBearer: { invalid: 'config' }
            } ) ).rejects.toThrow( 'Validation failed: Invalid configuration, Missing required field' )
        } )

    } )


    describe( 'getRouteConfig', () => {

        let middleware

        beforeEach( async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )
            middleware = await McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                }
            } )
        } )


        test( 'returns route config for valid route', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockMcpAuthMiddlewareImpl.getRouteConfig.mockReturnValue( {
                authType: 'staticBearer',
                tokenSecret: 'test-token-123456'
            } )

            const config = middleware.getRouteConfig( { routePath: '/api' } )

            expect( config ).toEqual( {
                authType: 'staticBearer',
                tokenSecret: 'test-token-123456'
            } )
            expect( mockValidation.validationGetRouteConfig ).toHaveBeenCalledWith( { routePath: '/api' } )
        } )


        test( 'throws error when route validation fails', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: false,
                messages: [ 'Invalid route path' ]
            } )

            expect( () => {
                middleware.getRouteConfig( { routePath: 'invalid-route' } )
            } ).toThrow( 'Validation failed: Invalid route path' )
        } )

    } )


    describe( 'getRouteClient', () => {

        let middleware

        beforeEach( async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )
            middleware = await McpAuthMiddleware.create( {
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com',
                        mcpId: 'res_test123',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        resource: 'mcp:tools:*',
                        scope: 'mcp:tools:* mcp:resources:read'
                    }
                }
            } )
        } )


        test( 'returns route client for valid route', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockMcpAuthMiddlewareImpl.getRouteClient.mockReturnValue( {
                provider: 'scalekit'
            } )

            const client = middleware.getRouteClient( { routePath: '/oauth' } )

            expect( client ).toEqual( { provider: 'scalekit' } )
            expect( mockValidation.validationGetRouteConfig ).toHaveBeenCalledWith( { routePath: '/oauth' } )
        } )


        test( 'throws error when route validation fails', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: false,
                messages: [ 'Route not found' ]
            } )

            expect( () => {
                middleware.getRouteClient( { routePath: '/nonexistent' } )
            } ).toThrow( 'Validation failed: Route not found' )
        } )

    } )


    describe( 'router', () => {

        test( 'returns router from implementation', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockMcpAuthMiddlewareImpl.router.mockReturnValue( 'mock-router' )

            const middleware = await McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                }
            } )

            const router = middleware.router()

            expect( router ).toBe( 'mock-router' )
            expect( mockMcpAuthMiddlewareImpl.router ).toHaveBeenCalled()
        } )

    } )


    describe( 'getRoutes', () => {

        test( 'returns routes from implementation', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockMcpAuthMiddlewareImpl.getRoutes.mockReturnValue( [ '/api', '/oauth' ] )

            const middleware = await McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api' ]
                },
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com',
                        mcpId: 'res_test123',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        resource: 'mcp:tools:*',
                        scope: 'mcp:tools:* mcp:resources:read'
                    }
                }
            } )

            const routes = middleware.getRoutes()

            expect( routes ).toEqual( [ '/api', '/oauth' ] )
            expect( mockMcpAuthMiddlewareImpl.getRoutes ).toHaveBeenCalled()
        } )

    } )


    describe( 'Route Management', () => {

        test( 'getRoutes returns configured routes from mixed auth types', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockMcpAuthMiddlewareImpl.getRoutes.mockReturnValue( [ '/api', '/data', '/oauth' ] )

            const middleware = await McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api', '/data' ]
                },
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com',
                        mcpId: 'res_test123',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        resource: 'mcp:tools:*',
                        scope: 'mcp:tools:* mcp:resources:read'
                    }
                }
            } )

            const routes = middleware.getRoutes()

            expect( routes ).toEqual( [ '/api', '/data', '/oauth' ] )
            expect( mockMcpAuthMiddlewareImpl.getRoutes ).toHaveBeenCalled()
        } )

    } )

} )