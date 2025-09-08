import { jest } from '@jest/globals'
import { TestUtils } from '../../helpers/utils.mjs'

const { ProviderFactory } = await import( '../../../src/providers/ProviderFactory.mjs' )
const { Auth0Provider } = await import( '../../../src/providers/Auth0Provider.mjs' )
const { BaseProvider } = await import( '../../../src/providers/BaseProvider.mjs' )

// Test configuration using .auth.env.example
const config = {
    envPath: '../../../.auth.env.example',
    providerUrl: 'https://your-first-auth0-domain.auth0.com',
    realm: 'test-realm',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    providerName: 'auth0',
    silent: true
}

const validAuth0Config = {
    providerUrl: config.providerUrl,
    realm: config.realm,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    providerName: config.providerName
}

describe( 'ProviderFactory', () => {
    afterEach( () => {
        jest.resetAllMocks()
    } )

    describe( 'createProvider', () => {
        test( 'creates Auth0Provider successfully with valid configuration', () => {
            const provider = ProviderFactory.createProvider( {
                provider: 'auth0',
                config: validAuth0Config,
                silent: true
            } )
            
            expect( provider ).toBeInstanceOf( Auth0Provider )
            expect( provider.getConfig() ).toBe( validAuth0Config )
            expect( provider.isSilent() ).toBe( true )
        } )

        test( 'creates Auth0Provider with default silent=false', () => {
            const provider = ProviderFactory.createProvider( {
                provider: 'auth0',
                config: validAuth0Config
            } )
            
            expect( provider ).toBeInstanceOf( Auth0Provider )
            expect( provider.isSilent() ).toBe( false )
        } )

        test( 'throws error with invalid provider type', () => {
            expect( () => {
                ProviderFactory.createProvider( {
                    provider: 'unsupported-provider',
                    config: validAuth0Config
                } )
            } ).toThrow( 'Provider validation failed: Unsupported provider: unsupported-provider. Supported: auth0' )
        } )

        test( 'covers default case by mocking validation', () => {
            // Temporarily mock BaseProvider.validateProviderConfig to bypass validation
            const originalValidate = BaseProvider.validateProviderConfig
            BaseProvider.validateProviderConfig = jest.fn().mockReturnValue( { status: true, messages: [] } )

            expect( () => {
                ProviderFactory.createProvider( {
                    provider: 'unknown-provider',
                    config: validAuth0Config,
                    silent: true
                } )
            } ).toThrow( 'Unsupported provider: unknown-provider. Supported providers: auth0' )

            // Restore original method
            BaseProvider.validateProviderConfig = originalValidate
        } )

        test( 'throws error with null provider', () => {
            expect( () => {
                ProviderFactory.createProvider( {
                    provider: null,
                    config: validAuth0Config
                } )
            } ).toThrow( 'Provider validation failed: Provider is required' )
        } )

        test( 'throws error with missing config', () => {
            expect( () => {
                ProviderFactory.createProvider( {
                    provider: 'auth0',
                    config: null
                } )
            } ).toThrow( 'Provider validation failed: Provider configuration is required' )
        } )

        test( 'throws error with invalid config type', () => {
            expect( () => {
                ProviderFactory.createProvider( {
                    provider: 'auth0',
                    config: 'invalid-config'
                } )
            } ).toThrow( 'Provider validation failed: Provider configuration is required' )
        } )

        test( 'throws error when Auth0 specific validation fails', () => {
            const invalidAuth0Config = {
                providerUrl: 'https://not-auth0-domain.com', // Invalid domain
                clientId: 'test-client',
                clientSecret: 'test-secret'
            }

            expect( () => {
                ProviderFactory.createProvider( {
                    provider: 'auth0',
                    config: invalidAuth0Config
                } )
            } ).toThrow( 'Auth0 provider validation failed: Auth0 provider requires auth0.com domain in providerUrl' )
        } )

        test( 'throws error when Auth0 config missing required fields', () => {
            const incompleteAuth0Config = {
                providerUrl: validAuth0Config.providerUrl
                // Missing clientId and clientSecret
            }

            expect( () => {
                ProviderFactory.createProvider( {
                    provider: 'auth0',
                    config: incompleteAuth0Config
                } )
            } ).toThrow( 'Auth0 provider validation failed: Auth0 config missing required fields: clientId, clientSecret' )
        } )

        test( 'handles multiple Auth0 validation errors', () => {
            const invalidAuth0Config = {
                providerUrl: 'https://invalid-domain.com',
                requiredScopes: 'not-an-array'
                // Missing required fields
            }

            expect( () => {
                ProviderFactory.createProvider( {
                    provider: 'auth0',
                    config: invalidAuth0Config
                } )
            } ).toThrow( 'Auth0 provider validation failed' )
        } )
    } )

    describe( 'getSupportedProviders', () => {
        test( 'returns array of supported providers', () => {
            const providers = ProviderFactory.getSupportedProviders()
            
            expect( Array.isArray( providers ) ).toBe( true )
            expect( providers ).toContain( 'auth0' )
            expect( providers ).toHaveLength( 1 )
        } )
    } )

    describe( 'validateRealmsByRoute', () => {
        const validRealmsByRoute = {
            '/api/v1': {
                providerName: 'auth0',
                providerUrl: validAuth0Config.providerUrl,
                clientId: validAuth0Config.clientId,
                clientSecret: validAuth0Config.clientSecret
            },
            '/api/v2': {
                providerName: 'auth0',
                providerUrl: 'https://another-domain.auth0.com',
                clientId: 'client-2',
                clientSecret: 'secret-2'
            }
        }

        test( 'validates correct realmsByRoute configuration', () => {
            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: validRealmsByRoute } )
            
            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )

        test( 'fails validation with null realmsByRoute', () => {
            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: null } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'realmsByRoute must be a non-array object' )
        } )

        test( 'fails validation with array realmsByRoute', () => {
            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: [] } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'realmsByRoute must be a non-array object' )
        } )

        test( 'fails validation with string realmsByRoute', () => {
            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: 'invalid' } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'realmsByRoute must be a non-array object' )
        } )

        test( 'fails validation with missing providerName', () => {
            const invalidRealmsByRoute = {
                '/api/v1': {
                    // Missing providerName
                    providerUrl: validAuth0Config.providerUrl,
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                }
            }

            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: invalidRealmsByRoute } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api/v1": Missing providerName field' )
        } )

        test( 'fails validation with invalid provider configuration', () => {
            const invalidRealmsByRoute = {
                '/api/v1': {
                    providerName: 'auth0',
                    providerUrl: 'https://invalid-domain.com', // Invalid domain
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                }
            }

            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: invalidRealmsByRoute } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api/v1": Auth0 provider validation failed: Auth0 provider requires auth0.com domain in providerUrl' )
        } )

        test( 'fails validation with unsupported provider', () => {
            const invalidRealmsByRoute = {
                '/api/v1': {
                    providerName: 'keycloak',
                    providerUrl: validAuth0Config.providerUrl,
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                }
            }

            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: invalidRealmsByRoute } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Route "/api/v1": Provider validation failed: Unsupported provider: keycloak. Supported: auth0' )
        } )

        test( 'accumulates multiple validation errors', () => {
            const invalidRealmsByRoute = {
                '/api/v1': {
                    // Missing providerName
                    providerUrl: validAuth0Config.providerUrl,
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                },
                '/api/v2': {
                    providerName: 'auth0',
                    providerUrl: 'https://invalid-domain.com',
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                }
            }

            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: invalidRealmsByRoute } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toHaveLength( 2 )
            expect( result.messages ).toContain( 'Route "/api/v1": Missing providerName field' )
            expect( result.messages ).toContain( 'Route "/api/v2": Auth0 provider validation failed: Auth0 provider requires auth0.com domain in providerUrl' )
        } )

        test( 'handles empty realmsByRoute object', () => {
            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: {} } )
            
            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )
    } )

    describe( 'createProvidersForRoutes', () => {
        const validRealmsByRoute = {
            '/api/v1': {
                providerName: 'auth0',
                providerUrl: validAuth0Config.providerUrl,
                realm: 'realm-1',
                clientId: 'client-1',
                clientSecret: 'secret-1'
            },
            '/api/v2': {
                providerName: 'auth0',
                providerUrl: 'https://second-domain.auth0.com',
                realm: 'realm-2',
                clientId: 'client-2',
                clientSecret: 'secret-2'
            }
        }

        test( 'creates providers for valid routes with silent=true', () => {
            const { providers } = ProviderFactory.createProvidersForRoutes( {
                realmsByRoute: validRealmsByRoute,
                silent: true
            } )
            
            expect( providers ).toBeDefined()
            expect( Object.keys( providers ) ).toHaveLength( 2 )
            
            expect( providers['/api/v1'] ).toBeInstanceOf( Auth0Provider )
            expect( providers['/api/v2'] ).toBeInstanceOf( Auth0Provider )
            
            expect( providers['/api/v1'].isSilent() ).toBe( true )
            expect( providers['/api/v2'].isSilent() ).toBe( true )
        } )

        test( 'creates providers with default silent=false', () => {
            const { providers } = ProviderFactory.createProvidersForRoutes( {
                realmsByRoute: validRealmsByRoute
            } )
            
            expect( providers['/api/v1'].isSilent() ).toBe( false )
            expect( providers['/api/v2'].isSilent() ).toBe( false )
        } )

        test( 'providers have correct configurations', () => {
            const { providers } = ProviderFactory.createProvidersForRoutes( {
                realmsByRoute: validRealmsByRoute,
                silent: true
            } )
            
            const provider1Config = providers['/api/v1'].getConfig()
            const provider2Config = providers['/api/v2'].getConfig()
            
            expect( provider1Config.clientId ).toBe( 'client-1' )
            expect( provider1Config.realm ).toBe( 'realm-1' )
            
            expect( provider2Config.clientId ).toBe( 'client-2' )
            expect( provider2Config.realm ).toBe( 'realm-2' )
        } )

        test( 'throws error with invalid realmsByRoute', () => {
            expect( () => {
                ProviderFactory.createProvidersForRoutes( {
                    realmsByRoute: null
                } )
            } ).toThrow( 'Route validation failed: realmsByRoute must be a non-array object' )
        } )

        test( 'throws error with missing providerName', () => {
            const invalidRealmsByRoute = {
                '/api/v1': {
                    // Missing providerName
                    providerUrl: validAuth0Config.providerUrl,
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                }
            }

            expect( () => {
                ProviderFactory.createProvidersForRoutes( {
                    realmsByRoute: invalidRealmsByRoute
                } )
            } ).toThrow( 'Route validation failed: Route "/api/v1": Missing providerName field' )
        } )

        test( 'throws error with invalid provider configuration', () => {
            const invalidRealmsByRoute = {
                '/api/v1': {
                    providerName: 'auth0',
                    providerUrl: 'https://invalid-domain.com',
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                }
            }

            expect( () => {
                ProviderFactory.createProvidersForRoutes( {
                    realmsByRoute: invalidRealmsByRoute
                } )
            } ).toThrow( 'Route validation failed: Route "/api/v1": Auth0 provider validation failed: Auth0 provider requires auth0.com domain in providerUrl' )
        } )

        test( 'handles empty realmsByRoute object', () => {
            const { providers } = ProviderFactory.createProvidersForRoutes( {
                realmsByRoute: {}
            } )
            
            expect( providers ).toEqual( {} )
        } )

        test( 'accumulates validation errors from multiple routes', () => {
            const invalidRealmsByRoute = {
                '/api/v1': {
                    // Missing providerName
                    providerUrl: validAuth0Config.providerUrl,
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                },
                '/api/v2': {
                    providerName: 'unsupported-provider',
                    providerUrl: validAuth0Config.providerUrl,
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                }
            }

            expect( () => {
                ProviderFactory.createProvidersForRoutes( {
                    realmsByRoute: invalidRealmsByRoute
                } )
            } ).toThrow( 'Route validation failed' )
        } )
    } )

    describe( 'Edge Cases', () => {
        test( 'handles undefined parameters gracefully', () => {
            expect( () => {
                ProviderFactory.createProvider( {
                    provider: undefined,
                    config: undefined
                } )
            } ).toThrow( 'Provider validation failed: Provider is required' )
        } )

        test( 'validateRealmsByRoute handles undefined parameter', () => {
            const result = ProviderFactory.validateRealmsByRoute( { realmsByRoute: undefined } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'realmsByRoute must be a non-array object' )
        } )

        test( 'createProvidersForRoutes handles complex route paths', () => {
            const complexRealmsByRoute = {
                '/api/v1/auth/oauth2': {
                    providerName: 'auth0',
                    providerUrl: validAuth0Config.providerUrl,
                    clientId: validAuth0Config.clientId,
                    clientSecret: validAuth0Config.clientSecret
                }
            }

            const { providers } = ProviderFactory.createProvidersForRoutes( {
                realmsByRoute: complexRealmsByRoute,
                silent: true
            } )
            
            expect( providers['/api/v1/auth/oauth2'] ).toBeInstanceOf( Auth0Provider )
        } )
    } )
} )