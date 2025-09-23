import { describe, it, expect, jest, beforeEach } from '@jest/globals'
import { FreeRouteMiddleware } from '../../src/authTypes/FreeRouteMiddleware.mjs'


describe( 'FreeRouteMiddleware', () => {
    let consoleSpy

    beforeEach( () => {
        jest.clearAllMocks()
        consoleSpy = jest.spyOn( console, 'log' ).mockImplementation( () => {} )
    } )


    describe( '.create()', () => {
        it( 'creates middleware instance with default parameters', async () => {
            const middleware = await FreeRouteMiddleware.create( {} )

            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )


        it( 'creates middleware instance with custom parameters', async () => {
            const options = { customOption: 'test' }
            const attachedRoutes = ['/api', '/tools']
            const silent = true

            const middleware = await FreeRouteMiddleware.create( {
                options,
                attachedRoutes,
                silent
            } )

            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )


        it( 'logs authentication info when silent is false', async () => {
            await FreeRouteMiddleware.create( {
                options: {},
                attachedRoutes: [],
                silent: false
            } )

            expect( consoleSpy ).toHaveBeenCalledWith( expect.stringContaining( 'AUTHENTICATION MIDDLEWARE' ) )
            expect( consoleSpy ).toHaveBeenCalledWith( expect.stringContaining( 'Free Route (No Authentication)' ) )
        } )


        it( 'does not log when silent is true', async () => {
            await FreeRouteMiddleware.create( {
                options: {},
                attachedRoutes: [],
                silent: true
            } )

            expect( consoleSpy ).not.toHaveBeenCalled()
        } )
    } )


    describe( '.router()', () => {
        it( 'returns express router function', async () => {
            const middleware = await FreeRouteMiddleware.create( { silent: true } )
            const router = middleware.router()

            expect( router ).toBeDefined()
            expect( typeof router ).toBe( 'function' )
        } )


        it( 'middleware passes through all requests', async () => {
            const middleware = await FreeRouteMiddleware.create( { silent: true } )
            const router = middleware.router()

            const mockReq = {
                method: 'GET',
                path: '/test'
            }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle

            middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockNext ).toHaveBeenCalledWith()
        } )


        it( 'processes request without logging when silent is false', async () => {
            const middleware = await FreeRouteMiddleware.create( { silent: false } )
            const router = middleware.router()

            const mockReq = {
                method: 'POST',
                path: '/api/test'
            }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle
            const initialCallCount = consoleSpy.mock.calls.length

            middlewareFunction( mockReq, mockRes, mockNext )

            // Should not log any request-level information (verbosity reduced)
            expect( consoleSpy.mock.calls.length ).toBe( initialCallCount )
            expect( mockNext ).toHaveBeenCalledWith()
        } )


        it( 'does not log access when silent is true', async () => {
            const middleware = await FreeRouteMiddleware.create( { silent: true } )
            const router = middleware.router()

            const mockReq = {
                method: 'GET',
                path: '/test'
            }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle

            middlewareFunction( mockReq, mockRes, mockNext )

            expect( consoleSpy ).not.toHaveBeenCalled()
            expect( mockNext ).toHaveBeenCalledWith()
        } )
    } )
} )