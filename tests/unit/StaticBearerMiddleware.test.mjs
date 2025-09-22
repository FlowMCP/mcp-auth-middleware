import { describe, it, expect, jest, beforeEach } from '@jest/globals'
import { StaticBearerMiddleware } from '../../src/authTypes/StaticBearerMiddleware.mjs'


describe( 'StaticBearerMiddleware', () => {
    let consoleSpy

    beforeEach( () => {
        jest.clearAllMocks()
        consoleSpy = jest.spyOn( console, 'log' ).mockImplementation( () => {} )
    } )


    describe( '.create()', () => {
        it( 'creates middleware instance with valid bearerToken', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                silent: true
            } )

            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )


        it( 'throws error when bearerToken is missing', async () => {
            const options = {}

            await expect( StaticBearerMiddleware.create( { options } ) )
                .rejects
                .toThrow( 'StaticBearer: Missing required option: bearerToken' )
        } )


        it( 'logs authentication info when silent is false', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const attachedRoutes = ['/api']

            await StaticBearerMiddleware.create( {
                options,
                attachedRoutes,
                silent: false
            } )

            expect( consoleSpy ).toHaveBeenCalledWith( expect.stringContaining( 'Static Bearer Token' ) )
            expect( consoleSpy ).toHaveBeenCalledWith( expect.stringContaining( '16 characters' ) )
            expect( consoleSpy ).toHaveBeenCalledWith( expect.stringContaining( 'test***' ) )
        } )


        it( 'does not log when silent is true', async () => {
            const options = { bearerToken: 'test-token-12345' }

            await StaticBearerMiddleware.create( {
                options,
                silent: true
            } )

            expect( consoleSpy ).not.toHaveBeenCalled()
        } )
    } )


    describe( '.router()', () => {
        it( 'returns express router function', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                silent: true
            } )
            const router = middleware.router()

            expect( router ).toBeDefined()
            expect( typeof router ).toBe( 'function' )
        } )


        it( 'passes through request when no attachedRoutes', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                attachedRoutes: [],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = { path: '/test' }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockNext ).toHaveBeenCalledWith()
        } )


        it( 'authenticates request for attached routes with valid token', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {
                    authorization: 'Bearer test-token-12345'
                }
            }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockNext ).toHaveBeenCalledWith()
        } )


        it( 'returns 401 for attached routes with invalid token', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {
                    authorization: 'Bearer wrong-token'
                }
            }
            const mockRes = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockRes.status ).toHaveBeenCalledWith( 401 )
            expect( mockRes.set ).toHaveBeenCalledWith( 'WWW-Authenticate', 'Bearer realm="Static Token"' )
            expect( mockRes.end ).toHaveBeenCalled()
            expect( mockNext ).not.toHaveBeenCalled()
        } )


        it( 'returns 401 for attached routes with missing token', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {}
            }
            const mockRes = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockRes.status ).toHaveBeenCalledWith( 401 )
            expect( mockNext ).not.toHaveBeenCalled()
        } )


        it( 'handles root path authentication correctly', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                attachedRoutes: ['/'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/',
                headers: {
                    authorization: 'Bearer test-token-12345'
                }
            }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockNext ).toHaveBeenCalledWith()
        } )


        it( 'does not authenticate non-root paths when only root is attached', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                attachedRoutes: ['/'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {}
            }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockNext ).toHaveBeenCalledWith()
        } )


        it( 'logs authentication success when silent is false', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: false
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {
                    authorization: 'Bearer test-token-12345'
                }
            }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( consoleSpy ).toHaveBeenCalledWith( expect.stringContaining( 'AUTH SUCCESS' ) )
        } )


        it( 'logs authentication failure when silent is false', async () => {
            const options = { bearerToken: 'test-token-12345' }
            const middleware = await StaticBearerMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: false
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {
                    authorization: 'Bearer wrong-token'
                }
            }
            const mockRes = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }
            const mockNext = jest.fn()

            const middlewareFunction = router.stack[0].handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( consoleSpy ).toHaveBeenCalledWith( expect.stringContaining( 'AUTH FAILED' ) )
        } )
    } )
} )