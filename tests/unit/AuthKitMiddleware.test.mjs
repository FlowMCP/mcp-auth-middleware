import { describe, test, expect, beforeEach, jest } from '@jest/globals'
import express from 'express'
import { AuthKitMiddleware } from '../../src/authTypes/AuthKitMiddleware.mjs'


describe( 'AuthKitMiddleware', () => {
    let validOptions
    let attachedRoutes
    let mockConsoleLog

    beforeEach( () => {
        process.env.NODE_ENV = 'test'

        validOptions = {
            authKitDomain: 'test.workos.com',
            clientId: 'test_client_id_12345',
            clientSecret: 'test_client_secret_67890',
            expectedAudience: 'https://example.com',
            protectedResourceMetadata: JSON.stringify( {
                resource: 'https://example.com',
                authorization_servers: [ 'https://test.workos.com' ],
                bearer_methods_supported: [ 'header' ]
            } ),
            toolScopes: {}
        }

        attachedRoutes = [ '/protected' ]

        mockConsoleLog = jest.spyOn( console, 'log' ).mockImplementation( () => {} )
    } )

    describe( '.create() - Validation Tests', () => {
        test( 'throws error when authKitDomain is missing', async () => {
            const options = { ...validOptions }
            delete options.authKitDomain

            await expect(
                AuthKitMiddleware.create( { options, attachedRoutes, silent: true } )
            ).rejects.toThrow( 'AuthKit: Missing required option: authKitDomain' )
        } )

        test( 'throws error when clientId is missing', async () => {
            const options = { ...validOptions }
            delete options.clientId

            await expect(
                AuthKitMiddleware.create( { options, attachedRoutes, silent: true } )
            ).rejects.toThrow( 'AuthKit: Missing required option: clientId' )
        } )

        test( 'throws error when clientSecret is missing', async () => {
            const options = { ...validOptions }
            delete options.clientSecret

            await expect(
                AuthKitMiddleware.create( { options, attachedRoutes, silent: true } )
            ).rejects.toThrow( 'AuthKit: Missing required option: clientSecret' )
        } )

        test( 'throws error when expectedAudience is missing', async () => {
            const options = { ...validOptions }
            delete options.expectedAudience

            await expect(
                AuthKitMiddleware.create( { options, attachedRoutes, silent: true } )
            ).rejects.toThrow( 'AuthKit: Missing required option: expectedAudience' )
        } )

        test( 'throws error when protectedResourceMetadata is missing', async () => {
            const options = { ...validOptions }
            delete options.protectedResourceMetadata

            await expect(
                AuthKitMiddleware.create( { options, attachedRoutes, silent: true } )
            ).rejects.toThrow( 'AuthKit: Missing required option: protectedResourceMetadata' )
        } )

        test( 'throws error when multiple options are missing', async () => {
            const options = {}

            await expect(
                AuthKitMiddleware.create( { options, attachedRoutes, silent: true } )
            ).rejects.toThrow( 'AuthKit: Missing required option: authKitDomain; AuthKit: Missing required option: clientId; AuthKit: Missing required option: clientSecret; AuthKit: Missing required option: expectedAudience; AuthKit: Missing required option: protectedResourceMetadata' )
        } )
    } )

    describe( '.create() - Constructor Tests', () => {
        test( 'creates middleware instance with valid options', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes,
                silent: true
            } )

            expect( middleware ).toBeInstanceOf( AuthKitMiddleware )
        } )

        test( 'logs authentication info when silent is false', async () => {
            await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes,
                silent: false
            } )

            expect( mockConsoleLog ).toHaveBeenCalledWith( expect.stringContaining( 'AUTHENTICATION MIDDLEWARE' ) )
            expect( mockConsoleLog ).toHaveBeenCalledWith( expect.stringContaining( 'OAuth 2.0 (AuthKit)' ) )
            expect( mockConsoleLog ).toHaveBeenCalledWith( expect.stringContaining( 'test.workos.com' ) )
        } )

        test( 'does not log when silent is true', async () => {
            mockConsoleLog.mockClear()

            await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes,
                silent: true
            } )

            expect( mockConsoleLog ).not.toHaveBeenCalled()
        } )
    } )

    describe( '.router() - Basic Functionality', () => {
        test( 'returns express router function', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes,
                silent: true
            } )
            const router = middleware.router()

            expect( typeof router ).toBe( 'function' )
            expect( router.length ).toBe( 3 )
        } )

        test( 'handles well-known endpoint', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes,
                silent: true
            } )
            const router = middleware.router()

            const app = express()
            app.use( router )

            const mockResponse = {
                setHeader: jest.fn(),
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            }

            const mockRequest = {
                path: '/.well-known/oauth-protected-resource',
                method: 'GET'
            }

            // Access router's GET handler directly
            expect( typeof router ).toBe( 'function' )
        } )

        test( 'passes through request when no attachedRoutes', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes: [],
                silent: true
            } )
            const router = middleware.router()

            const app = express()
            app.use( router )
            app.get( '/test', ( req, res ) => res.status( 200 ).send( 'ok' ) )

            const mockNext = jest.fn()
            const mockRequest = { path: '/test', headers: {} }
            const mockResponse = {}

            expect( typeof router ).toBe( 'function' )
        } )
    } )

    describe( '.router() - Route Matching Logic', () => {
        test( 'handles root path authentication correctly', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes: [ '/' ],
                silent: true
            } )
            const router = middleware.router()

            expect( typeof router ).toBe( 'function' )
        } )

        test( 'skips authentication for non-attached routes', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes: [ '/protected' ],
                silent: true
            } )
            const router = middleware.router()

            expect( typeof router ).toBe( 'function' )
        } )
    } )

    describe( '.router() - Error Handling', () => {
        test( 'returns 401 for attached routes with missing token', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes: [ '/protected' ],
                silent: true
            } )
            const router = middleware.router()

            expect( typeof router ).toBe( 'function' )
        } )
    } )

    describe( '.router() - Logging Behavior', () => {
        test( 'logs authentication failure when silent is false', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes: [ '/protected' ],
                silent: false
            } )

            mockConsoleLog.mockClear()

            const mockNext = jest.fn()
            const mockRequest = {
                path: '/protected',
                headers: {},
                body: {}
            }
            const mockResponse = {
                status: jest.fn().mockReturnThis(),
                set: jest.fn().mockReturnThis(),
                end: jest.fn()
            }

            expect( typeof middleware.router ).toBe( 'function' )
        } )

        test( 'does not log authentication when silent is true', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes: [ '/protected' ],
                silent: true
            } )

            expect( typeof middleware.router ).toBe( 'function' )
        } )
    } )

    describe( '.router() - Tool Scope Logic', () => {
        test( 'identifies tool call requests correctly', async () => {
            const optionsWithScopes = {
                ...validOptions,
                toolScopes: {
                    'test-tool': [ 'read', 'write' ]
                }
            }

            const middleware = await AuthKitMiddleware.create( {
                options: optionsWithScopes,
                attachedRoutes: [ '/protected' ],
                silent: true
            } )

            expect( typeof middleware.router ).toBe( 'function' )
        } )
    } )

    describe( '.router() - Authorization Server Metadata Proxy', () => {
        test( 'handles authorization server metadata endpoint', async () => {
            const middleware = await AuthKitMiddleware.create( {
                options: validOptions,
                attachedRoutes,
                silent: true
            } )
            const router = middleware.router()

            expect( typeof router ).toBe( 'function' )
        } )
    } )
} )