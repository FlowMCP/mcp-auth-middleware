import { jest } from '@jest/globals'
import { TestUtils } from '../../helpers/utils.mjs'

const { Auth0Provider } = await import( '../../../src/providers/Auth0Provider.mjs' )

// Test configuration using .auth.env.example
const config = {
    envPath: '../../../.auth.env.example',
    providerUrl: 'https://your-first-auth0-domain.auth0.com',
    realm: 'test-realm',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    requiredScopes: [ 'openid', 'profile', 'email' ],
    resourceUri: 'http://localhost:3000',
    silent: true
}

describe( 'Auth0Provider', () => {
    let provider
    
    beforeEach( () => {
        provider = new Auth0Provider( {
            config: config,
            silent: config.silent
        } )
    } )

    afterEach( () => {
        jest.resetAllMocks()
    } )

    describe( 'constructor', () => {
        test( 'creates Auth0Provider instance with valid configuration', () => {
            expect( provider ).toBeInstanceOf( Auth0Provider )
            expect( provider ).toBeDefined()
        } )

        test( 'creates Auth0Provider with silent mode', () => {
            const silentProvider = new Auth0Provider( {
                config: config,
                silent: true
            } )
            
            expect( silentProvider ).toBeDefined()
        } )
    } )

    describe( 'detectProviderType', () => {
        test( 'detects Auth0 provider correctly with auth0.com domain', () => {
            const result = provider.detectProviderType( {
                providerUrl: 'https://your-domain.auth0.com'
            } )
            
            expect( result ).toBe( true )
        } )

        test( 'detects Auth0 provider with different subdomain', () => {
            const result = provider.detectProviderType( {
                providerUrl: 'https://different-domain.auth0.com'
            } )
            
            expect( result ).toBe( true )
        } )

        test( 'rejects non-Auth0 domains', () => {
            const result = provider.detectProviderType( {
                providerUrl: 'https://example.com'
            } )
            
            expect( result ).toBe( false )
        } )

        test( 'handles undefined providerUrl', () => {
            const result = provider.detectProviderType( {
                providerUrl: undefined
            } )
            
            expect( result ).toBe( false )
        } )

        test( 'handles null providerUrl', () => {
            const result = provider.detectProviderType( {
                providerUrl: null
            } )
            
            expect( result ).toBe( false )
        } )
    } )

    describe( 'normalizeConfiguration', () => {
        test( 'normalizes complete Auth0 configuration', () => {
            const testConfig = {
                providerUrl: config.providerUrl,
                realm: config.realm,
                clientId: config.clientId,
                clientSecret: config.clientSecret,
                requiredScopes: config.requiredScopes,
                resourceUri: config.resourceUri
            }

            const { normalizedConfig } = provider.normalizeConfiguration( { config: testConfig } )

            expect( normalizedConfig ).toEqual( {
                providerUrl: config.providerUrl,
                realm: config.realm,
                clientId: config.clientId,
                clientSecret: config.clientSecret,
                requiredScopes: config.requiredScopes,
                resourceUri: config.resourceUri,
                authFlow: 'authorization_code'
            } )
        } )

        test( 'applies default values for missing fields', () => {
            const minimalConfig = {
                providerUrl: config.providerUrl,
                clientId: config.clientId,
                clientSecret: config.clientSecret,
                resourceUri: config.resourceUri
            }

            const { normalizedConfig } = provider.normalizeConfiguration( { config: minimalConfig } )

            expect( normalizedConfig.realm ).toBe( 'auth0' )
            expect( normalizedConfig.requiredScopes ).toEqual( [ 'openid', 'profile', 'email' ] )
            expect( normalizedConfig.authFlow ).toBe( 'authorization_code' )
        } )

        test( 'preserves custom realm when provided', () => {
            const customConfig = {
                ...config,
                realm: 'custom-realm'
            }

            const { normalizedConfig } = provider.normalizeConfiguration( { config: customConfig } )

            expect( normalizedConfig.realm ).toBe( 'custom-realm' )
        } )

        test( 'preserves custom scopes when provided', () => {
            const customScopes = [ 'read:users', 'write:users' ]
            const customConfig = {
                ...config,
                requiredScopes: customScopes
            }

            const { normalizedConfig } = provider.normalizeConfiguration( { config: customConfig } )

            expect( normalizedConfig.requiredScopes ).toEqual( customScopes )
        } )
    } )

    describe( 'generateEndpoints', () => {
        test( 'generates correct Auth0 endpoints', () => {
            const { endpoints } = provider.generateEndpoints( { config } )

            expect( endpoints ).toEqual( {
                authorizationEndpoint: `${config.providerUrl}/authorize`,
                tokenEndpoint: `${config.providerUrl}/oauth/token`,
                deviceAuthorizationEndpoint: `${config.providerUrl}/oauth/device/code`,
                jwksUrl: `${config.providerUrl}/.well-known/jwks.json`,
                userInfoUrl: `${config.providerUrl}/userinfo`,
                introspectionUrl: `${config.providerUrl}/oauth/token/introspection`,
                discoveryUrl: `${config.providerUrl}/.well-known/openid_configuration`
            } )
        } )

        test( 'generates endpoints with different provider URL', () => {
            const altConfig = {
                ...config,
                providerUrl: 'https://different-domain.auth0.com'
            }

            const { endpoints } = provider.generateEndpoints( { config: altConfig } )

            expect( endpoints.authorizationEndpoint ).toBe( 'https://different-domain.auth0.com/authorize' )
            expect( endpoints.tokenEndpoint ).toBe( 'https://different-domain.auth0.com/oauth/token' )
            expect( endpoints.jwksUrl ).toBe( 'https://different-domain.auth0.com/.well-known/jwks.json' )
        } )
    } )

    describe( 'validateAuth0Config', () => {
        test( 'validates complete Auth0 configuration successfully', () => {
            const result = Auth0Provider.validateAuth0Config( { config } )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )

        test( 'fails validation with missing required fields', () => {
            const incompleteConfig = {
                providerUrl: config.providerUrl
                // Missing clientId and clientSecret
            }

            const result = Auth0Provider.validateAuth0Config( { config: incompleteConfig } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Auth0 config missing required fields: clientId, clientSecret' )
        } )

        test( 'fails validation with invalid Auth0 domain', () => {
            const invalidConfig = {
                ...config,
                providerUrl: 'https://not-auth0-domain.com'
            }

            const result = Auth0Provider.validateAuth0Config( { config: invalidConfig } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Auth0 provider requires auth0.com domain in providerUrl' )
        } )

        test( 'fails validation with non-array scopes', () => {
            const invalidConfig = {
                ...config,
                requiredScopes: 'not-an-array'
            }

            const result = Auth0Provider.validateAuth0Config( { config: invalidConfig } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Auth0 requiredScopes must be an array' )
        } )

        test( 'accumulates multiple validation errors', () => {
            const invalidConfig = {
                requiredScopes: 'not-an-array'
                // Missing all required fields
            }

            const result = Auth0Provider.validateAuth0Config( { config: invalidConfig } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toHaveLength( 2 )
            expect( result.messages ).toContain( 'Auth0 config missing required fields: providerUrl, clientId, clientSecret' )
            expect( result.messages ).toContain( 'Auth0 requiredScopes must be an array' )
        } )
    } )

    describe( 'getProviderName', () => {
        test( 'returns correct provider name', () => {
            const name = provider.getProviderName()
            expect( name ).toBe( 'auth0' )
        } )
    } )

    describe( 'getDisplayName', () => {
        test( 'returns correct display name', () => {
            const displayName = provider.getDisplayName()
            expect( displayName ).toBe( 'Auth0' )
        } )
    } )

    describe( 'getSupportedFlows', () => {
        test( 'returns supported OAuth flows', () => {
            const flows = Auth0Provider.getSupportedFlows()
            
            expect( flows ).toEqual( [ 'authorization_code', 'client_credentials', 'refresh_token' ] )
            expect( flows ).toHaveLength( 3 )
        } )
    } )

    describe( 'getDefaultScopes', () => {
        test( 'returns default OAuth scopes', () => {
            const scopes = Auth0Provider.getDefaultScopes()
            
            expect( scopes ).toEqual( [ 'openid', 'profile', 'email' ] )
            expect( scopes ).toHaveLength( 3 )
        } )
    } )

    describe( 'Edge Cases', () => {
        test( 'handles empty configuration object', () => {
            const result = Auth0Provider.validateAuth0Config( { config: {} } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Auth0 config missing required fields: providerUrl, clientId, clientSecret' )
        } )

        test( 'handles null configuration', () => {
            const result = Auth0Provider.validateAuth0Config( { config: null } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Auth0 config must be a valid object' )
        } )

        test( 'handles undefined configuration', () => {
            const result = Auth0Provider.validateAuth0Config( { config: undefined } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Auth0 config must be a valid object' )
        } )

        test( 'handles non-object configuration', () => {
            const result = Auth0Provider.validateAuth0Config( { config: 'not-an-object' } )
            
            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Auth0 config must be a valid object' )
        } )

        test( 'normalizeConfiguration handles missing config properties gracefully', () => {
            const emptyConfig = {}
            
            const { normalizedConfig } = provider.normalizeConfiguration( { config: emptyConfig } )
            
            expect( normalizedConfig.realm ).toBe( 'auth0' )
            expect( normalizedConfig.requiredScopes ).toEqual( [ 'openid', 'profile', 'email' ] )
            expect( normalizedConfig.authFlow ).toBe( 'authorization_code' )
        } )
    } )
} )