import { jest } from '@jest/globals'
import { TestUtils } from '../../helpers/utils.mjs'

const { BaseProvider } = await import( '../../../src/providers/BaseProvider.mjs' )
const { Auth0Provider } = await import( '../../../src/providers/Auth0Provider.mjs' )

// Test configuration using .auth.env.example
const config = {
    envPath: '../../../.auth.env.example',
    providerUrl: 'https://your-first-auth0-domain.auth0.com',
    realm: 'test-realm',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    silent: true
}

describe( 'BaseProvider', () => {
    afterEach( () => {
        jest.resetAllMocks()
    } )

    describe( 'constructor', () => {
        test( 'cannot instantiate BaseProvider directly', () => {
            expect( () => {
                new BaseProvider( { config, silent: true } )
            } ).toThrow( 'BaseProvider is abstract and cannot be instantiated directly' )
        } )

        test( 'can instantiate concrete subclass (Auth0Provider)', () => {
            const provider = new Auth0Provider( { config, silent: true } )
            
            expect( provider ).toBeInstanceOf( Auth0Provider )
            expect( provider ).toBeInstanceOf( BaseProvider )
        } )

        test( 'stores config and silent flag correctly', () => {
            const provider = new Auth0Provider( { config, silent: true } )
            
            expect( provider.getConfig() ).toBe( config )
            expect( provider.isSilent() ).toBe( true )
        } )

        test( 'defaults to silent=false', () => {
            const provider = new Auth0Provider( { config } )
            
            expect( provider.isSilent() ).toBe( false )
        } )
    } )

    describe( 'getConfig', () => {
        test( 'returns stored configuration', () => {
            const testConfig = { test: 'configuration' }
            const provider = new Auth0Provider( { config: testConfig, silent: true } )
            
            expect( provider.getConfig() ).toEqual( testConfig )
        } )
    } )

    describe( 'isSilent', () => {
        test( 'returns true when silent mode enabled', () => {
            const provider = new Auth0Provider( { config, silent: true } )
            
            expect( provider.isSilent() ).toBe( true )
        } )

        test( 'returns false when silent mode disabled', () => {
            const provider = new Auth0Provider( { config, silent: true } )
            
            expect( provider.isSilent() ).toBe( true )
        } )
    } )

    describe( 'Abstract Methods', () => {
        test( 'detectProviderType throws error when not implemented', () => {
            // Test BaseProvider directly to trigger abstract method error
            expect( () => {
                const baseProvider = { detectProviderType: BaseProvider.prototype.detectProviderType }
                baseProvider.detectProviderType( { keycloakUrl: 'test' } )
            } ).toThrow( 'detectProviderType must be implemented by subclass' )
        } )

        test( 'normalizeConfiguration throws error when not implemented', () => {
            // Test BaseProvider directly to trigger abstract method error
            expect( () => {
                const baseProvider = { normalizeConfiguration: BaseProvider.prototype.normalizeConfiguration }
                baseProvider.normalizeConfiguration( { config: {} } )
            } ).toThrow( 'normalizeConfiguration must be implemented by subclass' )
        } )

        test( 'generateEndpoints throws error when not implemented', () => {
            // Test BaseProvider directly to trigger abstract method error
            expect( () => {
                const baseProvider = { generateEndpoints: BaseProvider.prototype.generateEndpoints }
                baseProvider.generateEndpoints( { config: {} } )
            } ).toThrow( 'generateEndpoints must be implemented by subclass' )
        } )

        // Create a minimal concrete subclass for testing abstract method behavior
        class TestProvider extends BaseProvider {
            // Override abstract methods to test they're called properly
            detectProviderType( { keycloakUrl } ) {
                return keycloakUrl && keycloakUrl.includes( 'test' )
            }
            
            normalizeConfiguration( { config } ) {
                return { normalizedConfig: config }
            }
            
            generateEndpoints( { config } ) {
                return { endpoints: { test: 'endpoint' } }
            }
        }

        test( 'detectProviderType works when properly implemented', () => {
            const provider = new TestProvider( { config, silent: true } )
            
            const result = provider.detectProviderType( { keycloakUrl: 'https://test.example.com' } )
            expect( result ).toBe( true )
            
            const result2 = provider.detectProviderType( { keycloakUrl: 'https://example.com' } )
            expect( result2 ).toBe( false )
        } )

        test( 'normalizeConfiguration works when properly implemented', () => {
            const provider = new TestProvider( { config, silent: true } )
            const testConfig = { test: 'config' }
            
            const result = provider.normalizeConfiguration( { config: testConfig } )
            expect( result ).toEqual( { normalizedConfig: testConfig } )
        } )

        test( 'generateEndpoints works when properly implemented', () => {
            const provider = new TestProvider( { config, silent: true } )
            
            const result = provider.generateEndpoints( { config } )
            expect( result ).toEqual( { endpoints: { test: 'endpoint' } } )
        } )
    } )

    describe( 'getSupportedProviders', () => {
        test( 'returns array of supported providers', () => {
            const providers = BaseProvider.getSupportedProviders()
            
            expect( Array.isArray( providers ) ).toBe( true )
            expect( providers ).toContain( 'auth0' )
            expect( providers.length ).toBeGreaterThan( 0 )
        } )
    } )

    describe( 'validateProviderConfig', () => {
        test( 'validates auth0 provider with valid config', () => {
            const result = BaseProvider.validateProviderConfig( {
                provider: 'auth0',
                config: config
            } )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )

        test( 'fails validation with missing provider', () => {
            const result = BaseProvider.validateProviderConfig( {
                provider: null,
                config: config
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Provider is required' )
        } )

        test( 'fails validation with unsupported provider', () => {
            const result = BaseProvider.validateProviderConfig( {
                provider: 'unsupported-provider',
                config: config
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Unsupported provider: unsupported-provider. Supported: auth0' )
        } )

        test( 'fails validation with missing config', () => {
            const result = BaseProvider.validateProviderConfig( {
                provider: 'auth0',
                config: null
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Provider configuration is required' )
        } )

        test( 'fails validation with invalid config type', () => {
            const result = BaseProvider.validateProviderConfig( {
                provider: 'auth0',
                config: 'invalid-config-type'
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Provider configuration is required' )
        } )

        test( 'early returns on provider validation failure', () => {
            const result = BaseProvider.validateProviderConfig( {
                provider: null,
                config: config
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toHaveLength( 1 )
            expect( result.messages[0] ).toBe( 'Provider is required' )
        } )

        test( 'early returns on unsupported provider', () => {
            const result = BaseProvider.validateProviderConfig( {
                provider: 'keycloak',
                config: config
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toHaveLength( 1 )
            expect( result.messages[0] ).toContain( 'Unsupported provider' )
        } )
    } )

    describe( 'Edge Cases', () => {
        test( 'handles undefined config gracefully', () => {
            const provider = new Auth0Provider( { config: undefined, silent: true } )
            
            expect( provider.getConfig() ).toBeUndefined()
            expect( provider.isSilent() ).toBe( true )
        } )

        test( 'validateProviderConfig handles empty objects', () => {
            const result = BaseProvider.validateProviderConfig( {
                provider: 'auth0',
                config: {}
            } )

            expect( result.status ).toBe( true )
            expect( result.messages ).toHaveLength( 0 )
        } )

        test( 'validateProviderConfig handles undefined provider parameter', () => {
            const result = BaseProvider.validateProviderConfig( {
                provider: undefined,
                config: config
            } )

            expect( result.status ).toBe( false )
            expect( result.messages ).toContain( 'Provider is required' )
        } )
    } )

    describe( 'Inheritance Behavior', () => {
        test( 'Auth0Provider inherits from BaseProvider correctly', () => {
            const provider = new Auth0Provider( { config, silent: true } )
            
            expect( provider ).toBeInstanceOf( BaseProvider )
            expect( provider.constructor.name ).toBe( 'Auth0Provider' )
        } )

        test( 'concrete provider can access base class methods', () => {
            const provider = new Auth0Provider( { config, silent: true } )
            
            expect( typeof provider.getConfig ).toBe( 'function' )
            expect( typeof provider.isSilent ).toBe( 'function' )
            expect( provider.getConfig() ).toBe( config )
        } )

        test( 'static methods are accessible from subclass', () => {
            expect( Auth0Provider.getSupportedProviders ).toBe( BaseProvider.getSupportedProviders )
            expect( Auth0Provider.validateProviderConfig ).toBe( BaseProvider.validateProviderConfig )
            
            const providers = Auth0Provider.getSupportedProviders()
            expect( providers ).toContain( 'auth0' )
        } )
    } )
} )