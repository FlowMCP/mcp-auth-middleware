import { jest } from '@jest/globals'
import { OAuth21Auth0Provider } from '../../../../src/authTypes/oauth21_auth0/OAuth21Auth0Provider.mjs'
import { completeOAuth21Auth0Config, minimalOAuth21Auth0Config } from '../../../helpers/oauth21-auth0-template.mjs'

describe('OAuth21Auth0Provider', () => {
    let provider
    let mockConfig

    beforeEach(() => {
        mockConfig = {
            authType: 'oauth21_auth0',
            providerUrl: 'https://tenant.auth0.com',
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            scope: 'openid profile email',
            audience: 'https://api.example.com',
            realm: 'test-realm',
            authFlow: 'authorization_code',
            requiredScopes: [ 'openid', 'profile', 'email' ],
            requiredRoles: [ 'user' ]
        }
    })

    describe('constructor and initialization', () => {
        test('creates provider with config and default silent', () => {
            provider = new OAuth21Auth0Provider({ config: mockConfig })

            expect(provider).toBeInstanceOf(OAuth21Auth0Provider)
        })

        test('creates provider with silent option', () => {
            provider = new OAuth21Auth0Provider({ config: mockConfig, silent: true })

            expect(provider).toBeInstanceOf(OAuth21Auth0Provider)
        })
    })

    describe('detectProviderType', () => {
        beforeEach(() => {
            provider = new OAuth21Auth0Provider({ config: mockConfig, silent: true })
        })

        test('detects Auth0 provider URL correctly', () => {
            const result = provider.detectProviderType({ 
                providerUrl: 'https://tenant.auth0.com' 
            })

            expect(result).toBe(true)
        })

        test('detects Auth0 subdomain provider URL', () => {
            const result = provider.detectProviderType({ 
                providerUrl: 'https://custom-tenant.auth0.com' 
            })

            expect(result).toBe(true)
        })

        test('rejects non-Auth0 provider URLs', () => {
            const result = provider.detectProviderType({ 
                providerUrl: 'https://accounts.google.com' 
            })

            expect(result).toBe(false)
        })

        test('rejects empty provider URL', () => {
            const result = provider.detectProviderType({ 
                providerUrl: '' 
            })

            expect(result).toBe(false)
        })

        test('rejects null provider URL', () => {
            const result = provider.detectProviderType({ 
                providerUrl: null 
            })

            expect(result).toBe(false)
        })

        test('rejects undefined provider URL', () => {
            const result = provider.detectProviderType({})

            expect(result).toBe(false)
        })
    })

    describe('normalizeConfiguration', () => {
        beforeEach(() => {
            provider = new OAuth21Auth0Provider({ config: mockConfig, silent: true })
        })

        test('normalizes complete configuration', () => {
            const result = provider.normalizeConfiguration({ config: mockConfig })

            expect(result.normalizedConfig).toEqual({
                authType: 'oauth21_auth0',
                providerUrl: 'https://tenant.auth0.com',
                clientId: 'test-client-id',
                clientSecret: 'test-client-secret',
                scope: 'openid profile email',
                audience: 'https://api.example.com',
                realm: 'test-realm',
                authFlow: 'authorization_code',
                requiredScopes: [ 'openid', 'profile', 'email' ],
                requiredRoles: [ 'user' ]
            })
        })

        test('preserves all provided configuration fields', () => {
            const customConfig = {
                ...mockConfig,
                realm: 'custom-realm',
                scope: 'custom:read custom:write',
                additionalField: 'custom-value'
            }

            const result = provider.normalizeConfiguration({ config: customConfig })

            expect(result.normalizedConfig.realm).toBe('custom-realm')
            expect(result.normalizedConfig.scope).toBe('custom:read custom:write')
            expect(result.normalizedConfig.additionalField).toBe('custom-value')
            expect(result.normalizedConfig.authFlow).toBe('authorization_code')
            expect(result.normalizedConfig.authType).toBe('oauth21_auth0')
        })

        test('preserves resourceUri when provided', () => {
            const configWithResourceUri = { ...mockConfig, resourceUri: 'https://resource.example.com' }

            const result = provider.normalizeConfiguration({ config: configWithResourceUri })

            expect(result.normalizedConfig.resourceUri).toBe('https://resource.example.com')
        })
    })

    describe('generateEndpoints', () => {
        beforeEach(() => {
            provider = new OAuth21Auth0Provider({ config: mockConfig, silent: true })
        })

        test('generates Auth0 endpoints from provider URL', () => {
            const result = provider.generateEndpoints({ config: mockConfig })

            expect(result.endpoints).toEqual({
                // OAuth 2.1 endpoints (RFC naming convention)
                authorizationEndpoint: 'https://tenant.auth0.com/authorize',
                tokenEndpoint: 'https://tenant.auth0.com/oauth/token',
                deviceAuthorizationEndpoint: 'https://tenant.auth0.com/oauth/device/code',
                jwksUrl: 'https://tenant.auth0.com/.well-known/jwks.json',
                userInfoUrl: 'https://tenant.auth0.com/userinfo',
                introspectionUrl: 'https://tenant.auth0.com/oauth/token/introspection',
                discoveryUrl: 'https://tenant.auth0.com/.well-known/openid_configuration'
            })
        })

        test('uses custom token endpoint when provided', () => {
            const configWithCustomToken = { 
                ...mockConfig, 
                tokenEndpoint: 'https://tenant.auth0.com/custom/token' 
            }

            const result = provider.generateEndpoints({ config: configWithCustomToken })

            expect(result.endpoints.tokenEndpoint).toBe('https://tenant.auth0.com/custom/token')
        })

        test('uses custom userinfo endpoint when provided', () => {
            const configWithCustomUserInfo = { 
                ...mockConfig, 
                userInfoEndpoint: 'https://tenant.auth0.com/custom/userinfo' 
            }

            const result = provider.generateEndpoints({ config: configWithCustomUserInfo })

            expect(result.endpoints.userInfoUrl).toBe('https://tenant.auth0.com/custom/userinfo')
        })
    })

    describe('validateOAuth21Auth0Config - static method', () => {
        test('validates complete valid configuration', () => {
            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: mockConfig })

            expect(result.status).toBe(true)
            expect(result.messages).toHaveLength(0)
        })

        test('rejects null config', () => {
            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: null })

            expect(result.status).toBe(false)
            expect(result.messages).toContain('OAuth21Auth0 config must be a valid object')
        })

        test('rejects undefined config', () => {
            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({})

            expect(result.status).toBe(false)
            expect(result.messages).toContain('OAuth21Auth0 config must be a valid object')
        })

        test('rejects non-object config', () => {
            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: 'invalid-config' })

            expect(result.status).toBe(false)
            expect(result.messages).toContain('OAuth21Auth0 config must be a valid object')
        })

        test('identifies missing required fields', () => {
            const incompleteConfig = {
                providerUrl: 'https://tenant.auth0.com'
                // Missing: clientId, clientSecret, scope, audience
            }

            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: incompleteConfig })

            expect(result.status).toBe(false)
            expect(result.messages).toContain('OAuth21Auth0 config missing required fields: clientId, clientSecret, scope, audience')
        })

        test('identifies multiple missing fields individually', () => {
            const partialConfig = {
                providerUrl: 'https://tenant.auth0.com',
                clientId: 'test-client'
                // Missing: clientSecret, scope, audience
            }

            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: partialConfig })

            expect(result.status).toBe(false)
            expect(result.messages).toContain('OAuth21Auth0 config missing required fields: clientSecret, scope, audience')
        })

        test('rejects non-Auth0 provider URL', () => {
            const invalidConfig = {
                ...mockConfig,
                providerUrl: 'https://accounts.google.com'
            }

            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: invalidConfig })

            expect(result.status).toBe(false)
            expect(result.messages).toContain('OAuth21Auth0 provider requires auth0.com domain in providerUrl')
        })

        test('rejects non-string scope', () => {
            const invalidConfig = {
                ...mockConfig,
                scope: 123 // Should be string
            }

            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: invalidConfig })

            expect(result.status).toBe(false)
            expect(result.messages).toContain('OAuth21Auth0 scope must be a string')
        })

        test('rejects array scope', () => {
            const invalidConfig = {
                ...mockConfig,
                scope: ['openid', 'profile', 'email'] // Should be string
            }

            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: invalidConfig })

            expect(result.status).toBe(false)
            expect(result.messages).toContain('OAuth21Auth0 scope must be a string')
        })

        test('rejects non-string audience', () => {
            const invalidConfig = {
                ...mockConfig,
                audience: 456 // Should be string
            }

            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: invalidConfig })

            expect(result.status).toBe(false)
            expect(result.messages).toContain('OAuth21Auth0 audience must be a string')
        })

        test('accumulates multiple validation errors', () => {
            const invalidConfig = {
                providerUrl: 'https://invalid-domain.com', // Wrong domain
                clientId: 'test-client',
                // Missing: clientSecret, scope, audience (scope and audience will be tested as wrong type)
                scope: 123, // Wrong type
                audience: ['invalid'] // Wrong type
            }

            const result = OAuth21Auth0Provider.validateOAuth21Auth0Config({ config: invalidConfig })

            expect(result.status).toBe(false)
            expect(result.messages.length).toBeGreaterThan(1)
            expect(result.messages).toContain('OAuth21Auth0 config missing required fields: clientSecret')
            expect(result.messages).toContain('OAuth21Auth0 provider requires auth0.com domain in providerUrl')
            expect(result.messages).toContain('OAuth21Auth0 scope must be a string')
            expect(result.messages).toContain('OAuth21Auth0 audience must be a string')
        })
    })

    describe('getter methods', () => {
        beforeEach(() => {
            provider = new OAuth21Auth0Provider({ config: mockConfig, silent: true })
        })

        test('getProviderName returns correct provider name', () => {
            const result = provider.getProviderName()

            expect(result).toBe('oauth21_auth0')
        })

        test('getDisplayName returns correct display name', () => {
            const result = provider.getDisplayName()

            expect(result).toBe('OAuth 2.1 with Auth0')
        })
    })

    describe('static methods', () => {
        test('getSupportedFlows returns correct OAuth flows', () => {
            const result = OAuth21Auth0Provider.getSupportedFlows()

            expect(result).toEqual(['authorization_code', 'client_credentials', 'refresh_token'])
            expect(result).toHaveLength(3)
        })

        test('getDefaultScopes returns correct default scopes', () => {
            const result = OAuth21Auth0Provider.getDefaultScopes()

            expect(result).toBe('openid profile email')
        })

        test('getAuthType returns correct auth type', () => {
            const result = OAuth21Auth0Provider.getAuthType()

            expect(result).toBe('oauth21_auth0')
        })
    })
})