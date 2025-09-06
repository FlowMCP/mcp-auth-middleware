import { jest } from '@jest/globals'

const { OAuthMiddleware } = await import( '../../src/index.mjs' )

describe( 'index.mjs', () => {
    test( 'exports OAuthMiddleware class', () => {
        expect( OAuthMiddleware ).toBeDefined()
        expect( typeof OAuthMiddleware ).toBe( 'function' )
    } )

    test( 'OAuthMiddleware has create method', () => {
        expect( typeof OAuthMiddleware.create ).toBe( 'function' )
    } )

    test( 'can create instance through exported class', () => {
        const { middleware } = OAuthMiddleware.create( {
            keycloakUrl: 'http://localhost:8080',
            realm: 'test-realm',
            clientId: 'test-client',
            clientSecret: 'test-secret',
            silent: true
        } )

        expect( middleware ).toBeDefined()
        expect( typeof middleware.mcp ).toBe( 'function' )
        expect( typeof middleware.mcpWithRBAC ).toBe( 'function' )
        expect( typeof middleware.wellKnownAuthorizationServer ).toBe( 'function' )
        expect( typeof middleware.wellKnownProtectedResource ).toBe( 'function' )
        expect( typeof middleware.wellKnownJwks ).toBe( 'function' )
    } )
} )