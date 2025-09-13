import { Validation } from '../../../src/task/Validation.mjs'


describe( 'Validation', () => {

    describe( 'validationCreate', () => {

        test( 'returns success for valid authType configuration', () => {
            const config = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email api:read api:write',
                        audience: 'https://api.example.com',
                        realm: 'api-realm',
                        authFlow: 'authorization_code',
                        requiredScopes: ['openid', 'profile', 'email', 'api:read', 'api:write'],
                        requiredRoles: ['user']
                    }
                },
                silent: true
            }

            const result = Validation.validationCreate( config )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )


        test( 'validates routes as required field', () => {
            const result = Validation.validationCreate( { silent: false } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'routes: Missing value' )
        } )


        test( 'validates routes as object', () => {
            const result = Validation.validationCreate( { 
                routes: 'not an object',
                silent: true
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'routes: Must be an object' )
        } )


        test( 'validates routes not as array', () => {
            const result = Validation.validationCreate( { 
                routes: [ 'not', 'an', 'object' ],
                silent: true
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'routes: Must be an object' )
        } )


        test( 'validates silent field type', () => {
            const result = Validation.validationCreate( { 
                routes: { '/api': {} },
                silent: 'not a boolean'
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'silent: Must be a boolean' )
        } )


        test( 'requires authType field in route config', () => {
            const result = Validation.validationCreate( { 
                routes: {
                    '/api': {
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": Missing required field: authType' )
        } )


        test( 'validates authType as string', () => {
            const result = Validation.validationCreate( { 
                routes: {
                    '/api': {
                        authType: 123, // Invalid type
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": authType must be a string' )
        } )


        test( 'validates oauth21_auth0 required fields', () => {
            const result = Validation.validationCreate( { 
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com'
                        // Missing: clientId, clientSecret, scope, audience
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages.some( msg => msg.includes( 'missing required fields' ) ) ).toBe( true )
        } )


        test( 'validates oauth21_auth0 provider URL format', () => {
            const result = Validation.validationCreate( { 
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'invalid-url', // Invalid URL format
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages.some( msg => msg.includes( 'valid URL' ) ) ).toBe( true )
        } )


        test( 'validates route path format', () => {
            const result = Validation.validationCreate( { 
                routes: {
                    'api': { // Should start with '/'
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client-id',
                        clientSecret: 'test-client-secret',
                        scope: 'openid profile email',
                        audience: 'https://api.example.com'
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "api": Must start with /' )
        } )


        test( 'validates multiple routes', () => {
            const config = {
                routes: {
                    '/api': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'api-client-id',
                        clientSecret: 'api-client-secret',
                        scope: 'openid profile email api:read',
                        audience: 'https://api.example.com',
                        realm: 'api-realm',
                        authFlow: 'authorization_code',
                        requiredScopes: ['openid', 'profile', 'email', 'api:read'],
                        requiredRoles: ['user']
                    },
                    '/admin': {
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://admin.auth0.com',
                        clientId: 'admin-client-id',
                        clientSecret: 'admin-client-secret',
                        scope: 'openid profile email admin:full',
                        audience: 'https://admin.example.com',
                        realm: 'admin-realm',
                        authFlow: 'authorization_code',
                        requiredScopes: ['openid', 'profile', 'email', 'admin:full'],
                        requiredRoles: ['admin']
                    }
                },
                silent: true
            }

            const result = Validation.validationCreate( config )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )


        test( 'validates route configuration objects', () => {
            const result = Validation.validationCreate( { 
                routes: {
                    '/api': 'not an object'
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": Configuration must be an object' )
        } )

    } )


    describe( 'validationGetRouteConfig', () => {

        test( 'validates routePath as required', () => {
            const result = Validation.validationGetRouteConfig( {} )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'routePath: Missing value' )
        } )


        test( 'validates routePath as string', () => {
            const result = Validation.validationGetRouteConfig( { routePath: 123 } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'routePath: Must be a string' )
        } )


        test( 'validates routePath format', () => {
            const result = Validation.validationGetRouteConfig( { routePath: 'api' } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'routePath: Must start with /' )
        } )


        test( 'returns success for valid routePath', () => {
            const result = Validation.validationGetRouteConfig( { routePath: '/api' } )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )

    } )


    describe( 'getSupportedAuthTypes', () => {

        test( 'returns supported auth types', () => {
            const result = Validation.getSupportedAuthTypes()

            expect( result ).toHaveProperty( 'authTypes' )
            expect( Array.isArray( result.authTypes ) || result.authTypes instanceof Map ).toBe( true )
        } )

    } )


    describe( 'validateAuthTypeConfig', () => {

        test( 'validates oauth21_auth0 configuration', () => {
            const result = Validation.validateAuthTypeConfig( {
                authType: 'oauth21_auth0',
                config: {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client-id',
                    clientSecret: 'test-client-secret',
                    scope: 'openid profile email',
                    audience: 'https://api.example.com',
                    realm: 'test-realm',
                    authFlow: 'authorization_code',
                    requiredScopes: ['openid', 'profile', 'email'],
                    requiredRoles: ['user']
                }
            } )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )


        test( 'fails for invalid oauth21_auth0 configuration', () => {
            const result = Validation.validateAuthTypeConfig( {
                authType: 'oauth21_auth0',
                config: {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://example.com' // Missing auth0.com domain
                    // Missing other required fields
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages.length ).toBeGreaterThan( 0 )
        } )

    } )

} )