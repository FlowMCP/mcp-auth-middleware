import { jest } from '@jest/globals'
import { McpAuthMiddleware } from '../../../src/task/McpAuthMiddleware.mjs'


describe( 'McpAuthMiddleware Input Validation', () => {
    const validStaticBearer = {
        tokenSecret: 'test-token-123456',
        attachedRoutes: [ '/api' ]
    }

    const validOAuth21 = {
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

    describe( 'Parameter object validation', () => {
        test( 'rejects undefined parameters', async () => {
            await expect( McpAuthMiddleware.create() ).rejects.toThrow( 'Input validation failed: Create parameters object is required' )
        } )

        test( 'rejects null parameters', async () => {
            await expect( McpAuthMiddleware.create( null ) ).rejects.toThrow( 'Input validation failed: Create parameters object is required' )
        } )

        test( 'handles unknown parameters with validation error', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                routes: { '/old': {} }, // Old API parameter should be rejected
                unknownParam: 'value',
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'Input validation failed: Unknown parameters: routes, unknownParam' )
        } )

        test( 'allows unprotected server (no auth configs)', async () => {
            const middleware = await McpAuthMiddleware.create( {
                silent: true, baseUrl: 'http://localhost:3000'
            } )
            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
            expect( middleware.getRoutes() ).toHaveLength( 0 )
        } )
    } )

    describe( 'staticBearer parameter validation', () => {
        test( 'validates staticBearer as object', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: 'not an object',
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'staticBearer: Must be an object' )
        } )

        test( 'validates staticBearer tokenSecret is required', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: {
                    attachedRoutes: [ '/api' ]
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'staticBearer.tokenSecret: Missing value' )
        } )

        test( 'validates staticBearer tokenSecret as string', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 123,
                    attachedRoutes: [ '/api' ]
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'staticBearer.tokenSecret: Must be a string' )
        } )

        test( 'validates staticBearer tokenSecret not empty', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: '   ',
                    attachedRoutes: [ '/api' ]
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'staticBearer.tokenSecret: Cannot be empty' )
        } )

        test( 'validates staticBearer attachedRoutes is required', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456'
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'staticBearer.attachedRoutes: Missing value' )
        } )

        test( 'validates staticBearer attachedRoutes as array', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: 'not an array'
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'staticBearer.attachedRoutes: Must be an array' )
        } )

        test( 'validates staticBearer attachedRoutes not empty', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: []
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'staticBearer.attachedRoutes: Cannot be empty array' )
        } )

        test( 'validates staticBearer route paths format', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ 'invalid-route' ]
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'staticBearer.attachedRoutes[0]: Must start with /' )
        } )
    } )

    describe( 'oauth21 parameter validation', () => {
        test( 'validates oauth21 as object', async () => {
            await expect( McpAuthMiddleware.create( {
                oauth21: 'not an object',
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'oauth21: Must be an object' )
        } )

        test( 'validates oauth21 authType is required', async () => {
            await expect( McpAuthMiddleware.create( {
                oauth21: {
                    attachedRoutes: [ '/oauth' ],
                    options: validOAuth21.options
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'oauth21.authType: Missing value' )
        } )

        test( 'validates oauth21 authType is oauth21_scalekit', async () => {
            await expect( McpAuthMiddleware.create( {
                oauth21: {
                    authType: 'oauth21_auth0', // Not supported anymore
                    attachedRoutes: [ '/oauth' ],
                    options: validOAuth21.options
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'oauth21.authType: Unsupported value "oauth21_auth0"' )
        } )

        test( 'validates oauth21 attachedRoutes is required', async () => {
            await expect( McpAuthMiddleware.create( {
                oauth21: {
                    authType: 'oauth21_scalekit',
                    options: validOAuth21.options
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'oauth21.attachedRoutes: Missing value' )
        } )

        test( 'validates oauth21 options is required', async () => {
            await expect( McpAuthMiddleware.create( {
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ]
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'oauth21.options: Missing value' )
        } )

        test( 'validates oauth21 options scalekit required fields', async () => {
            await expect( McpAuthMiddleware.create( {
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth' ],
                    options: {
                        providerUrl: 'https://auth.scalekit.com'
                        // Missing: mcpId, clientId, clientSecret, resource, scope
                    }
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'missing required fields' )
        } )
    } )

    describe( 'route conflicts validation', () => {
        test( 'detects route conflicts between staticBearer and oauth21', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: {
                    tokenSecret: 'test-token-123456',
                    attachedRoutes: [ '/api', '/data' ]
                },
                oauth21: {
                    authType: 'oauth21_scalekit',
                    attachedRoutes: [ '/oauth', '/api' ], // Conflict with /api
                    options: validOAuth21.options
                },
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'Route conflict: Routes cannot be in both staticBearer and oauth21 attachedRoutes: /api' )
        } )
    } )

    describe( 'silent parameter validation', () => {
        test( 'validates silent as boolean', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                silent: 'not a boolean'
            } ) ).rejects.toThrow( 'silent: Must be a boolean' )
        } )

        test( 'allows silent=true', async () => {
            const middleware = await McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                silent: true, baseUrl: 'http://localhost:3000'
            } )
            expect( middleware ).toBeDefined()
        } )

        test( 'allows silent=false', async () => {
            const middleware = await McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                silent: false,
                baseUrl: 'http://localhost:3000'
            } )
            expect( middleware ).toBeDefined()
        } )
    } )

    describe( 'baseUrl parameter validation', () => {
        test( 'validates baseUrl as string', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                baseUrl: 123,
                silent: true
            } ) ).rejects.toThrow( 'baseUrl: Must be a string' )
        } )

        test( 'validates baseUrl not empty', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                baseUrl: '   ',
                silent: true
            } ) ).rejects.toThrow( 'baseUrl: Cannot be empty' )
        } )

        test( 'validates baseUrl format', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                baseUrl: 'invalid-url',
                silent: true
            } ) ).rejects.toThrow( 'valid URL' )
        } )

        test( 'validates baseUrl protocol', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                baseUrl: 'ftp://example.com',
                silent: true
            } ) ).rejects.toThrow( 'baseUrl: Must use http:// or https:// protocol' )
        } )

        test( 'validates baseUrl has no path', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                baseUrl: 'https://example.com/path',
                silent: true
            } ) ).rejects.toThrow( 'baseUrl: Must not contain a path' )
        } )
    } )

    describe( 'forceHttps parameter validation', () => {
        test( 'validates forceHttps as boolean', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                forceHttps: 'not a boolean',
                silent: true, baseUrl: 'http://localhost:3000'
            } ) ).rejects.toThrow( 'forceHttps: Must be a boolean' )
        } )

        test( 'allows forceHttps=true', async () => {
            const middleware = await McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                forceHttps: true,
                silent: true, baseUrl: 'http://localhost:3000'
            } )
            expect( middleware ).toBeDefined()
        } )

        test( 'allows forceHttps=false', async () => {
            const middleware = await McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                forceHttps: false,
                silent: true, baseUrl: 'http://localhost:3000'
            } )
            expect( middleware ).toBeDefined()
        } )
    } )

    describe( 'multiple parameter validation errors', () => {
        test( 'reports multiple validation errors', async () => {
            await expect( McpAuthMiddleware.create( {
                staticBearer: 'not an object',
                oauth21: 'not an object',
                silent: 'not a boolean',
                baseUrl: 123,
                forceHttps: 'not a boolean'
            } ) ).rejects.toThrow( 'Input validation failed: silent: Must be a boolean, baseUrl: Must be a string, forceHttps: Must be a boolean' )
        } )
    } )

    describe( 'successful middleware creation', () => {
        test( 'creates middleware with staticBearer only', async () => {
            const middleware = await McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                silent: true, baseUrl: 'http://localhost:3000'
            } )
            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
            expect( middleware.getRoutes() ).toContain( '/api' )
        } )

        test( 'creates middleware with oauth21 only', async () => {
            const middleware = await McpAuthMiddleware.create( {
                oauth21: validOAuth21,
                silent: true, baseUrl: 'http://localhost:3000'
            } )
            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
            expect( middleware.getRoutes() ).toContain( '/oauth' )
        } )

        test( 'creates middleware with both staticBearer and oauth21', async () => {
            const middleware = await McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                oauth21: validOAuth21,
                silent: true, baseUrl: 'http://localhost:3000'
            } )
            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
            expect( middleware.getRoutes() ).toHaveLength( 2 )
            expect( middleware.getRoutes() ).toContain( '/api' )
            expect( middleware.getRoutes() ).toContain( '/oauth' )
        } )

        test( 'creates middleware with custom baseUrl and forceHttps', async () => {
            const middleware = await McpAuthMiddleware.create( {
                staticBearer: validStaticBearer,
                baseUrl: 'https://api.example.com',
                forceHttps: true,
                silent: true
            } )
            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )
    } )

} )