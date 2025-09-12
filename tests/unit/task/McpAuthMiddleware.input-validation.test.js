import { jest } from '@jest/globals'
import { McpAuthMiddleware } from '../../../src/task/McpAuthMiddleware.mjs'


describe( 'McpAuthMiddleware Input Validation', () => {
    const validRoutes = {
        '/test': {
            authType: 'oauth21_auth0',
            realm: 'test-realm',
            providerUrl: 'https://tenant.auth0.com',
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            audience: 'test-audience',
            scope: 'openid profile'
        }
    }

    describe( 'Parameter object validation', () => {
        test( 'rejects undefined parameters', async () => {
            await expect( McpAuthMiddleware.create() ).rejects.toThrow( 'Cannot destructure property' )
        } )

        test( 'rejects null parameters', async () => {
            await expect( McpAuthMiddleware.create( null ) ).rejects.toThrow( 'Cannot destructure property' )
        } )

        test( 'ignores unknown parameters (with destructuring)', async () => {
            // With the new API, unknown parameters are simply ignored due to destructuring
            const middleware = await McpAuthMiddleware.create( { 
                routes: validRoutes,
                unknownParam: 'value',  // This will be ignored
                anotherUnknown: true,   // This will be ignored  
                silent: true
            } )
            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )
    } )

    describe( 'routes parameter validation', () => {
        test( 'rejects missing routes', async () => {
            await expect( McpAuthMiddleware.create( { silent: true } ) ).rejects.toThrow( 'Input validation failed: routes: Missing value' )
        } )

        test( 'rejects null routes', async () => {
            await expect( McpAuthMiddleware.create( { routes: null } ) ).rejects.toThrow( 'Input validation failed: routes: Missing value' )
        } )

        test( 'rejects array for routes', async () => {
            await expect( McpAuthMiddleware.create( { routes: [ 'invalid' ] } ) ).rejects.toThrow( 'Input validation failed: routes: Must be an object' )
        } )

        test( 'rejects string for routes', async () => {
            await expect( McpAuthMiddleware.create( { routes: 'invalid' } ) ).rejects.toThrow( 'Input validation failed: routes: Must be an object' )
        } )

        test( 'rejects number for routes', async () => {
            await expect( McpAuthMiddleware.create( { routes: 123 } ) ).rejects.toThrow( 'Input validation failed: routes: Must be an object' )
        } )
    } )

    describe( 'silent parameter validation', () => {
        test( 'accepts valid silent=true', async () => {
            const middleware = await McpAuthMiddleware.create( { routes: validRoutes, silent: true } )
            expect( middleware ).toBeDefined()
        } )

        test( 'accepts valid silent=false', async () => {
            const middleware = await McpAuthMiddleware.create( { routes: validRoutes, silent: false } )
            expect( middleware ).toBeDefined()
        } )

        test( 'accepts undefined silent (default)', async () => {
            const middleware = await McpAuthMiddleware.create( { routes: validRoutes } )
            expect( middleware ).toBeDefined()
        } )

        test( 'rejects string for silent', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                silent: 'true' 
            } ) ).rejects.toThrow( 'Input validation failed: silent: Must be a boolean' )
        } )

        test( 'rejects number for silent', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                silent: 1 
            } ) ).rejects.toThrow( 'Input validation failed: silent: Must be a boolean' )
        } )
    } )

    describe( 'baseUrl parameter validation', () => {
        test( 'accepts valid HTTP baseUrl', async () => {
            const middleware = await McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: 'http://localhost:8080',
                silent: true 
            } )
            expect( middleware ).toBeDefined()
        } )

        test( 'accepts valid HTTPS baseUrl', async () => {
            const middleware = await McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: 'https://production.example.com',
                silent: true 
            } )
            expect( middleware ).toBeDefined()
        } )

        test( 'accepts valid baseUrl with port', async () => {
            const middleware = await McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: 'https://example.com:8443',
                silent: true 
            } )
            expect( middleware ).toBeDefined()
        } )

        test( 'accepts undefined baseUrl (default)', async () => {
            const middleware = await McpAuthMiddleware.create( { routes: validRoutes, silent: true } )
            expect( middleware ).toBeDefined()
        } )

        test( 'rejects empty baseUrl', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: '' 
            } ) ).rejects.toThrow( 'Input validation failed: baseUrl: Cannot be empty' )
        } )

        test( 'rejects whitespace-only baseUrl', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: '   ' 
            } ) ).rejects.toThrow( 'Input validation failed: baseUrl: Cannot be empty' )
        } )

        test( 'rejects number for baseUrl', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: 3000 
            } ) ).rejects.toThrow( 'Input validation failed: baseUrl: Must be a string' )
        } )

        test( 'rejects boolean for baseUrl', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: true 
            } ) ).rejects.toThrow( 'Input validation failed: baseUrl: Must be a string' )
        } )

        test( 'rejects invalid URL format', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: 'not-a-url' 
            } ) ).rejects.toThrow( 'Input validation failed: baseUrl: Invalid URL format' )
        } )

        test( 'rejects baseUrl with path', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: 'https://example.com/api' 
            } ) ).rejects.toThrow( 'Input validation failed: baseUrl: Must not contain a path (use protocol://host:port format)' )
        } )

        test( 'rejects baseUrl with query parameters', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: 'https://example.com?param=value' 
            } ) ).rejects.toThrow( 'Input validation failed: baseUrl: Must not contain query parameters' )
        } )

        test( 'rejects baseUrl with hash/fragment', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: 'https://example.com#section' 
            } ) ).rejects.toThrow( 'Input validation failed: baseUrl: Must not contain hash/fragment' )
        } )

        test( 'rejects unsupported protocol', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                baseUrl: 'ftp://example.com' 
            } ) ).rejects.toThrow( 'Input validation failed: baseUrl: Must use http:// or https:// protocol' )
        } )
    } )

    describe( 'forceHttps parameter validation', () => {
        test( 'accepts valid forceHttps=true', async () => {
            const middleware = await McpAuthMiddleware.create( { 
                routes: validRoutes, 
                forceHttps: true,
                silent: true 
            } )
            expect( middleware ).toBeDefined()
        } )

        test( 'accepts valid forceHttps=false', async () => {
            const middleware = await McpAuthMiddleware.create( { 
                routes: validRoutes, 
                forceHttps: false,
                silent: true 
            } )
            expect( middleware ).toBeDefined()
        } )

        test( 'accepts undefined forceHttps (default)', async () => {
            const middleware = await McpAuthMiddleware.create( { routes: validRoutes, silent: true } )
            expect( middleware ).toBeDefined()
        } )

        test( 'rejects string for forceHttps', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                forceHttps: 'true' 
            } ) ).rejects.toThrow( 'Input validation failed: forceHttps: Must be a boolean' )
        } )

        test( 'rejects number for forceHttps', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: validRoutes, 
                forceHttps: 1 
            } ) ).rejects.toThrow( 'Input validation failed: forceHttps: Must be a boolean' )
        } )
    } )

    describe( 'multiple parameter validation errors', () => {
        test( 'reports multiple validation errors', async () => {
            await expect( McpAuthMiddleware.create( { 
                routes: 'invalid',
                silent: 'not-boolean',
                baseUrl: 123,
                forceHttps: 'not-boolean'
                // unknownParam removed as it gets ignored by destructuring
            } ) ).rejects.toThrow( 'Input validation failed: routes: Must be an object, silent: Must be a boolean, baseUrl: Must be a string, forceHttps: Must be a boolean' )
        } )
    } )

    describe( 'successful validation scenarios', () => {
        test( 'accepts minimal valid configuration', async () => {
            const middleware = await McpAuthMiddleware.create( { routes: validRoutes, silent: true } )
            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )

        test( 'accepts full valid configuration', async () => {
            const middleware = await McpAuthMiddleware.create( { 
                routes: validRoutes,
                silent: true,
                baseUrl: 'https://production.example.com:8443',
                forceHttps: true
            } )
            expect( middleware ).toBeDefined()
            expect( typeof middleware.router ).toBe( 'function' )
        } )
    } )
} )