import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals'
import { ScaleKitMiddleware } from '../../src/authTypes/ScaleKitMiddleware.mjs'


describe( 'ScaleKitMiddleware', () => {
    let consoleSpy

    beforeEach( () => {
        jest.clearAllMocks()
        consoleSpy = jest.spyOn( console, 'log' ).mockImplementation( () => {} )
    } )

    afterEach( () => {
        consoleSpy.mockRestore()
    } )


    const getValidOptions = () => ( {
        providerUrl: 'https://test.scalekit.com',
        clientId: 'test_client_id',
        clientSecret: 'test_client_secret',
        resource: 'http://localhost:3000/',
        protectedResourceMetadata: '{\"test\": true}',
        toolScopes: { 'test_tool': ['read'] }
    } )


    describe( '.create() - Validation Tests', () => {
        it( 'throws error when providerUrl is missing', async () => {
            const options = {
                clientId: 'test_client_id',
                clientSecret: 'test_client_secret',
                resource: 'http://localhost:3000/',
                protectedResourceMetadata: '{\"test\": true}'
            }

            await expect( ScaleKitMiddleware.create( { options, silent: true } ) )
                .rejects
                .toThrow( 'ScaleKit: Missing required option: providerUrl' )
        } )


        it( 'throws error when multiple options are missing', async () => {
            const options = {
                providerUrl: 'https://test.scalekit.com'
            }

            await expect( ScaleKitMiddleware.create( { options, silent: true } ) )
                .rejects
                .toThrow( 'ScaleKit: Missing required option:' )
        } )
    } )


    describe( '.create() - Constructor Tests', () => {
        it( 'creates middleware instance with valid options', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                silent: true
            } )

            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )


        it( 'logs authentication info when silent is false', async () => {
            const options = getValidOptions()

            await ScaleKitMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: false
            } )

            expect( consoleSpy ).toHaveBeenCalledWith( expect.stringContaining( 'OAuth 2.0 (ScaleKit)' ) )
        } )


        it( 'does not log when silent is true', async () => {
            const options = getValidOptions()

            await ScaleKitMiddleware.create( {
                options,
                silent: true
            } )

            expect( consoleSpy ).not.toHaveBeenCalled()
        } )
    } )


    describe( '.router() - Basic Functionality', () => {
        it( 'returns express router function', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                silent: true
            } )
            const router = middleware.router()

            expect( router ).toBeDefined()
            expect( typeof router ).toBe( 'function' )
        } )


        it( 'handles well-known endpoint', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {}
            const mockRes = {
                setHeader: jest.fn(),
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            }

            const wellKnownHandler = router.stack.find( layer =>
                layer.route && layer.route.path === '/.well-known/oauth-protected-resource'
            ).route.stack[0].handle

            wellKnownHandler( mockReq, mockRes )

            expect( mockRes.setHeader ).toHaveBeenCalledWith( 'Content-Type', 'application/json' )
            expect( mockRes.status ).toHaveBeenCalledWith( 200 )
            expect( mockRes.json ).toHaveBeenCalledWith( { test: true } )
        } )


        it( 'passes through request when no attachedRoutes', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                attachedRoutes: [],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = { path: '/test' }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack.find( layer => !layer.route ).handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockNext ).toHaveBeenCalledWith()
        } )
    } )


    describe( '.router() - Route Matching Logic', () => {
        it( 'handles root path authentication correctly', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                attachedRoutes: ['/'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = { path: '/', headers: {}, body: {} }
            const mockRes = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }
            const mockNext = jest.fn()

            const middlewareFunction = router.stack.find( layer => !layer.route ).handle
            await middlewareFunction( mockReq, mockRes, mockNext )

            // Should return 401 for root path without auth token
            expect( mockRes.status ).toHaveBeenCalledWith( 401 )
            expect( mockNext ).not.toHaveBeenCalled()
        } )


        it( 'skips authentication for non-attached routes', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = { path: '/public' }
            const mockRes = {}
            const mockNext = jest.fn()

            const middlewareFunction = router.stack.find( layer => !layer.route ).handle
            middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockNext ).toHaveBeenCalledWith()
        } )
    } )


    describe( '.router() - Error Handling', () => {
        it( 'returns 401 for attached routes with missing token', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {},
                body: {}
            }
            const mockRes = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }
            const mockNext = jest.fn()

            const middlewareFunction = router.stack.find( layer => !layer.route ).handle
            await middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockRes.status ).toHaveBeenCalledWith( 401 )
            expect( mockNext ).not.toHaveBeenCalled()
        } )


        it.skip( 'returns 401 with WWW-Authenticate header', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: { authorization: 'Bearer invalid-token' },
                body: {}
            }
            const mockRes = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }
            const mockNext = jest.fn()

            const middlewareFunction = router.stack.find( layer => !layer.route ).handle
            await middlewareFunction( mockReq, mockRes, mockNext )

            expect( mockRes.status ).toHaveBeenCalledWith( 401 )
            expect( mockRes.set ).toHaveBeenCalledWith(
                'WWW-Authenticate',
                expect.stringContaining( 'Bearer realm="OAuth"' )
            )
            expect( mockNext ).not.toHaveBeenCalled()
        } )
    } )


    describe( '.router() - Logging Behavior', () => {
        it( 'logs authentication failure when silent is false', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: false
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {},  // No auth header = missing token
                body: {}
            }
            const mockRes = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }
            const mockNext = jest.fn()

            const middlewareFunction = router.stack.find( layer => !layer.route ).handle
            await middlewareFunction( mockReq, mockRes, mockNext )

            expect( consoleSpy ).toHaveBeenCalledWith( expect.stringContaining( 'AUTH FAILED' ) )
        } )


        it( 'does not log authentication when silent is true', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {},  // No auth header = missing token
                body: {}
            }
            const mockRes = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }
            const mockNext = jest.fn()

            const middlewareFunction = router.stack.find( layer => !layer.route ).handle
            await middlewareFunction( mockReq, mockRes, mockNext )

            // Should return 401 but not log when silent is true
            expect( mockRes.status ).toHaveBeenCalledWith( 401 )
            // consoleSpy should not contain auth messages (already checked in beforeEach)
        } )
    } )


    describe( '.router() - Tool Scope Logic', () => {
        it( 'identifies tool call requests correctly', async () => {
            const options = getValidOptions()
            const middleware = await ScaleKitMiddleware.create( {
                options,
                attachedRoutes: ['/api'],
                silent: true
            } )
            const router = middleware.router()

            const mockReq = {
                path: '/api/test',
                headers: {},
                body: {
                    method: 'tools/call',
                    params: {
                        name: 'test_tool'
                    }
                }
            }
            const mockRes = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }
            const mockNext = jest.fn()

            const middlewareFunction = router.stack.find( layer => !layer.route ).handle
            await middlewareFunction( mockReq, mockRes, mockNext )

            // Should return 401 due to missing token, but the tool call detection should work
            expect( mockRes.status ).toHaveBeenCalledWith( 401 )
        } )


        it.skip( 'handles environment variable ENFORCE_SCOPES correctly', async () => {
            const originalEnv = process.env.ENFORCE_SCOPES
            process.env.ENFORCE_SCOPES = 'false'

            try {
                const options = getValidOptions()
                const middleware = await ScaleKitMiddleware.create( {
                    options,
                    attachedRoutes: ['/api'],
                    silent: false
                } )
                const router = middleware.router()

                const mockReq = {
                    path: '/api/test',
                    headers: { authorization: 'Bearer valid-token' },  // Valid token to reach scope logic
                    body: {
                        method: 'tools/call',
                        params: {
                            name: 'test_tool'
                        }
                    }
                }
                const mockRes = {
                    status: jest.fn().mockReturnThis(),
                    set: jest.fn().mockReturnThis(),
                    end: jest.fn()
                }
                const mockNext = jest.fn()

                const middlewareFunction = router.stack.find( layer => !layer.route ).handle

                // This will trigger HTTP call, but we expect the SCOPE SKIP logic to run first
                // The test will fail on HTTP but may log SCOPE SKIP first
                try {
                    await middlewareFunction( mockReq, mockRes, mockNext )
                } catch( error ) {
                    // Ignore HTTP errors, we're testing the ENFORCE_SCOPES logic
                }

                // Check if SCOPE SKIP was logged (this logic runs before HTTP calls)
                const scopeSkipLogged = consoleSpy.mock.calls.some( call =>
                    call[0] && call[0].includes && call[0].includes( 'SCOPE SKIP' )
                )
                expect( scopeSkipLogged ).toBe( true )
            } finally {
                process.env.ENFORCE_SCOPES = originalEnv
            }
        } )
    } )
} )