import { jest } from '@jest/globals'

// Mock the OAuthMiddleware implementation
const mockOAuthMiddlewareImpl = {
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

jest.unstable_mockModule( '../../src/task/OAuthMiddleware.mjs', () => ({
    OAuthMiddleware: {
        create: jest.fn().mockResolvedValue( mockOAuthMiddlewareImpl )
    }
}) )

jest.unstable_mockModule( '../../src/task/Validation.mjs', () => ({
    Validation: mockValidation
}) )

const { OAuthMiddleware } = await import( '../../src/index.mjs' )


describe( 'OAuthMiddleware - Index Wrapper', () => {

    beforeEach( () => {
        jest.clearAllMocks()
    } )


    describe( 'create', () => {

        test( 'creates middleware successfully with valid config', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )

            const middleware = await OAuthMiddleware.create( {
                realmsByRoute: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )

            expect( middleware ).toBeDefined()
            expect( mockValidation.validationCreate ).toHaveBeenCalled()
        } )


        test( 'throws error when validation fails', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: false,
                messages: [ 'Invalid configuration', 'Missing required field' ]
            } )

            await expect( OAuthMiddleware.create( {
                realmsByRoute: { '/api': { invalid: 'config' } }
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
            middleware = await OAuthMiddleware.create( {
                realmsByRoute: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )
        } )


        test( 'returns route config for valid route', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockOAuthMiddlewareImpl.getRouteConfig.mockReturnValue( {
                providerUrl: 'https://auth.example.com'
            } )

            const config = middleware.getRouteConfig( '/api' )

            expect( config ).toEqual( { providerUrl: 'https://auth.example.com' } )
            expect( mockValidation.validationGetRouteConfig ).toHaveBeenCalledWith( { routePath: '/api' } )
        } )


        test( 'throws error when route validation fails', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: false,
                messages: [ 'Invalid route path' ]
            } )

            expect( () => {
                middleware.getRouteConfig( 'invalid-route' )
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
            middleware = await OAuthMiddleware.create( {
                realmsByRoute: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )
        } )


        test( 'returns route client for valid route', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockOAuthMiddlewareImpl.getRouteClient.mockReturnValue( {
                provider: 'auth0'
            } )

            const client = middleware.getRouteClient( '/api' )

            expect( client ).toEqual( { provider: 'auth0' } )
            expect( mockValidation.validationGetRouteConfig ).toHaveBeenCalledWith( { routePath: '/api' } )
        } )


        test( 'throws error when route validation fails', () => {
            mockValidation.validationGetRouteConfig.mockReturnValue( {
                status: false,
                messages: [ 'Route not found' ]
            } )

            expect( () => {
                middleware.getRouteClient( '/nonexistent' )
            } ).toThrow( 'Validation failed: Route not found' )
        } )

    } )


    describe( 'router', () => {

        test( 'returns router from implementation', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockOAuthMiddlewareImpl.router.mockReturnValue( 'mock-router' )

            const middleware = await OAuthMiddleware.create( {
                realmsByRoute: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )

            const router = middleware.router()

            expect( router ).toBe( 'mock-router' )
            expect( mockOAuthMiddlewareImpl.router ).toHaveBeenCalled()
        } )

    } )


    describe( 'getRoutes', () => {

        test( 'returns routes from implementation', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockOAuthMiddlewareImpl.getRoutes.mockReturnValue( [ '/api', '/admin' ] )

            const middleware = await OAuthMiddleware.create( {
                realmsByRoute: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )

            const routes = middleware.getRoutes()

            expect( routes ).toEqual( [ '/api', '/admin' ] )
            expect( mockOAuthMiddlewareImpl.getRoutes ).toHaveBeenCalled()
        } )

    } )


    describe( 'getRealms', () => {

        test( 'returns realms from implementation', async () => {
            mockValidation.validationCreate.mockReturnValue( {
                status: true,
                messages: []
            } )
            mockOAuthMiddlewareImpl.getRealms.mockReturnValue( [
                { route: '/api', realm: 'api-realm' }
            ] )

            const middleware = await OAuthMiddleware.create( {
                realmsByRoute: { '/api': { providerUrl: 'https://auth.example.com' } }
            } )

            const realms = middleware.getRealms()

            expect( realms ).toEqual( [ { route: '/api', realm: 'api-realm' } ] )
            expect( mockOAuthMiddlewareImpl.getRealms ).toHaveBeenCalled()
        } )

    } )

} )