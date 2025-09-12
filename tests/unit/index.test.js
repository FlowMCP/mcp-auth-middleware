import { jest } from '@jest/globals'

// Mock the McpAuthMiddleware implementation
const mockMcpAuthMiddlewareImpl = {
    router: jest.fn(),
    getRouteConfig: jest.fn(),
    getRouteClient: jest.fn(),
    getRoutes: jest.fn(),
    getRealms: jest.fn()
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

        test( 'creates middleware successfully with valid config', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )

            const middleware = await McpAuthMiddleware.create( {
                routes: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )

            expect( middleware ).toBeDefined()
            expect( mockValidation.validationCreate ).toHaveBeenCalled()
        } )


        test( 'creates middleware successfully with silent parameter', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )

            const middleware = await McpAuthMiddleware.create( {
                routes: { '/api': { providerUrl: 'https://auth.example.com' } },
                silent: true
            } )

            expect( middleware ).toBeDefined()
            expect( mockValidation.validationCreate ).toHaveBeenCalledWith( {
                routes: { '/api': { providerUrl: 'https://auth.example.com' } },
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
                routes: { '/api': { invalid: 'config' } }
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
                routes: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )
        } )


        test( 'returns route config for valid route', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockMcpAuthMiddlewareImpl.getRouteConfig.mockReturnValue( {
                providerUrl: 'https://auth.example.com'
            } )

            const config = middleware.getRouteConfig( { routePath: '/api' } )

            expect( config ).toEqual( { providerUrl: 'https://auth.example.com' } )
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
                routes: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )
        } )


        test( 'returns route client for valid route', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockMcpAuthMiddlewareImpl.getRouteClient.mockReturnValue( {
                provider: 'auth0'
            } )

            const client = middleware.getRouteClient( { routePath: '/api' } )

            expect( client ).toEqual( { provider: 'auth0' } )
            expect( mockValidation.validationGetRouteConfig ).toHaveBeenCalledWith( { routePath: '/api' } )
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
                routes: { '/api': { providerUrl: 'https://auth.example.com' } }
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
            mockMcpAuthMiddlewareImpl.getRoutes.mockReturnValue( [ '/api', '/admin' ] )

            const middleware = await McpAuthMiddleware.create( {
                routes: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )

            const routes = middleware.getRoutes()

            expect( routes ).toEqual( [ '/api', '/admin' ] )
            expect( mockMcpAuthMiddlewareImpl.getRoutes ).toHaveBeenCalled()
        } )

    } )


    describe( 'getRealms', () => {

        test( 'returns realms from implementation', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockMcpAuthMiddlewareImpl.getRealms.mockReturnValue( [
                { route: '/api', realm: 'api-realm' }
            ] )

            const middleware = await McpAuthMiddleware.create( {
                routes: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )

            const realms = middleware.getRealms()

            expect( realms ).toEqual( [ { route: '/api', realm: 'api-realm' } ] )
            expect( mockMcpAuthMiddlewareImpl.getRealms ).toHaveBeenCalled()
        } )

    } )

} )