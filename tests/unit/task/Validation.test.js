import { Validation } from '../../../src/task/Validation.mjs'


describe( 'Validation', () => {

    describe( 'validationCreate', () => {

        test( 'returns success for valid configuration', () => {
            const config = {
                realmsByRoute: {
                    '/api': {
                        providerName: 'auth0',
                        providerUrl: 'https://auth.example.com',
                        realm: 'test-realm',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        requiredScopes: [ 'read', 'write' ],
                        resourceUri: 'https://localhost:3000/api'
                    }
                },
                silent: true
            }

            const result = Validation.validationCreate( config )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )


        test( 'validates realmsByRoute as required field', () => {
            const result = Validation.validationCreate( { silent: false } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'realmsByRoute: Missing value' )
        } )


        test( 'validates realmsByRoute as object', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: 'not an object',
                silent: true
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'realmsByRoute: Must be an object' )
        } )


        test( 'validates realmsByRoute not as array', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: [ 'not', 'an', 'object' ],
                silent: true
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'realmsByRoute: Must be an object' )
        } )


        test( 'validates silent field type', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: { '/api': {} },
                silent: 'not a boolean'
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'silent: Must be a boolean' )
        } )


        test( 'validates route path format', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    'api-without-slash': {
                        providerName: 'auth0'
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "api-without-slash": Must start with /' )
        } )


        test( 'validates route configuration as object', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    '/api': 'not an object'
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": Configuration must be an object' )
        } )


        test( 'validates providerName field type', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    '/api': {
                        providerName: 123  // not a string
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": providerName must be a string' )
        } )


        test( 'validates unsupported provider name', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    '/api': {
                        providerName: 'unsupported-provider'
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": Unsupported provider "unsupported-provider". Supported providers: auth0' )
        } )


        test( 'validates providerUrl field type', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    '/api': {
                        providerName: 'auth0',
                        providerUrl: 123  // not a string
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": providerUrl must be a string' )
        } )


        test( 'validates realm field type', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    '/api': {
                        providerName: 'auth0',
                        realm: 123  // not a string
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": realm must be a string' )
        } )


        test( 'validates clientId field type', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    '/api': {
                        providerName: 'auth0',
                        clientId: 123  // not a string
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": clientId must be a string' )
        } )


        test( 'validates clientSecret field type', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    '/api': {
                        providerName: 'auth0',
                        clientSecret: 123  // not a string
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": clientSecret must be a string' )
        } )


        test( 'validates requiredScopes field type', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    '/api': {
                        providerName: 'auth0',
                        requiredScopes: 'not an array'  // not an array
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": requiredScopes must be an array' )
        } )


        test( 'validates resourceUri field type', () => {
            const result = Validation.validationCreate( { 
                realmsByRoute: {
                    '/api': {
                        providerName: 'auth0',
                        resourceUri: 123  // not a string
                    }
                }
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api": resourceUri must be a string' )
        } )

    } )


    describe( 'validationGetRouteConfig', () => {

        test( 'returns success for valid route path', () => {
            const result = Validation.validationGetRouteConfig( { routePath: '/api' } )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )


        test( 'validates routePath as required field', () => {
            const result = Validation.validationGetRouteConfig( {} )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'routePath: Missing value' )
        } )


        test( 'validates routePath field type', () => {
            const result = Validation.validationGetRouteConfig( { routePath: 123 } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'routePath: Must be a string' )
        } )


        test( 'validates routePath format', () => {
            const result = Validation.validationGetRouteConfig( { routePath: 'api-without-slash' } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'routePath: Must start with /' )
        } )

    } )

} )