import { StaticBearerProvider } from '../../../../src/authTypes/staticBearer/StaticBearerProvider.mjs'

describe('StaticBearerProvider', () => {
    let provider
    const mockConfig = {
        tokenSecret: 'test-token-123456'
    }

    beforeEach(() => {
        provider = new StaticBearerProvider({ config: mockConfig, silent: true })
    })

    describe('constructor', () => {
        test('creates provider with config', () => {
            expect(provider).toBeInstanceOf(StaticBearerProvider)
        })

        test('accepts silent parameter', () => {
            const silentProvider = new StaticBearerProvider({ config: mockConfig, silent: true })
            const verboseProvider = new StaticBearerProvider({ config: mockConfig, silent: false })
            
            expect(silentProvider).toBeInstanceOf(StaticBearerProvider)
            expect(verboseProvider).toBeInstanceOf(StaticBearerProvider)
        })
    })

    describe('detectProviderType', () => {
        test('detects valid staticBearer config', () => {
            const result = provider.detectProviderType({ 
                config: { tokenSecret: 'valid-token' } 
            })
            expect(result).toBe(true)
        })

        test('rejects config without tokenSecret', () => {
            const result = provider.detectProviderType({ 
                config: { clientId: 'test' } 
            })
            expect(result).toBe(false)
        })

        test('rejects config with non-string tokenSecret', () => {
            const result = provider.detectProviderType({ 
                config: { tokenSecret: 123 } 
            })
            expect(result).toBe(false)
        })

        test('rejects empty config', () => {
            const result = provider.detectProviderType({ config: {} })
            expect(result).toBe(false)
        })

        test('rejects null config', () => {
            const result = provider.detectProviderType({ config: null })
            expect(result).toBe(false)
        })
    })

    describe('normalizeConfiguration', () => {
        test('normalizes basic config', () => {
            const { normalizedConfig } = provider.normalizeConfiguration({ 
                config: { tokenSecret: 'test-token' } 
            })
            
            expect(normalizedConfig).toEqual({
                tokenSecret: 'test-token',
                authType: 'staticBearer',
                realm: 'static-bearer'
            })
        })

        test('trims token whitespace', () => {
            const { normalizedConfig } = provider.normalizeConfiguration({ 
                config: { tokenSecret: '  test-token  ' } 
            })
            
            expect(normalizedConfig.tokenSecret).toBe('test-token')
        })

        test('preserves token case', () => {
            const { normalizedConfig } = provider.normalizeConfiguration({ 
                config: { tokenSecret: 'Token123ABC' } 
            })
            
            expect(normalizedConfig.tokenSecret).toBe('Token123ABC')
        })
    })

    describe('generateEndpoints', () => {
        test('returns empty endpoints object', () => {
            const { endpoints } = provider.generateEndpoints()
            
            expect(endpoints).toEqual({})
            expect(Object.keys(endpoints)).toHaveLength(0)
        })
    })

    describe('static validateStaticBearerConfig', () => {
        test('validates correct config', () => {
            const result = StaticBearerProvider.validateStaticBearerConfig({ 
                config: { tokenSecret: 'valid-token-123456' } 
            })
            
            expect(result.status).toBe(true)
            expect(result.messages).toHaveLength(0)
        })

        test('rejects config without tokenSecret', () => {
            const result = StaticBearerProvider.validateStaticBearerConfig({ 
                config: {} 
            })
            
            expect(result.status).toBe(false)
            expect(result.messages).toContain('StaticBearer config missing required field: tokenSecret (must be string)')
        })

        test('rejects config with non-string tokenSecret', () => {
            const result = StaticBearerProvider.validateStaticBearerConfig({ 
                config: { tokenSecret: 123 } 
            })
            
            expect(result.status).toBe(false)
            expect(result.messages).toContain('StaticBearer config missing required field: tokenSecret (must be string)')
        })

        test('rejects token with Bearer prefix', () => {
            const result = StaticBearerProvider.validateStaticBearerConfig({ 
                config: { tokenSecret: 'Bearer abc123' } 
            })
            
            expect(result.status).toBe(false)
            expect(result.messages).toContain('StaticBearer token must not start with "Bearer" prefix')
        })

        test('rejects token with bearer prefix (lowercase)', () => {
            const result = StaticBearerProvider.validateStaticBearerConfig({ 
                config: { tokenSecret: 'bearer abc123' } 
            })
            
            expect(result.status).toBe(false)
            expect(result.messages).toContain('StaticBearer token must not start with "Bearer" prefix')
        })

        test('rejects token shorter than 8 characters', () => {
            const result = StaticBearerProvider.validateStaticBearerConfig({ 
                config: { tokenSecret: 'short' } 
            })
            
            expect(result.status).toBe(false)
            expect(result.messages).toContain('StaticBearer token must be at least 8 characters long')
        })

        test('accepts token exactly 8 characters', () => {
            const result = StaticBearerProvider.validateStaticBearerConfig({ 
                config: { tokenSecret: 'exactly8' } 
            })
            
            expect(result.status).toBe(true)
            expect(result.messages).toHaveLength(0)
        })

        test('rejects null config', () => {
            const result = StaticBearerProvider.validateStaticBearerConfig({ 
                config: null 
            })
            
            expect(result.status).toBe(false)
            expect(result.messages).toContain('StaticBearer config must be a valid object')
        })

        test('rejects non-object config', () => {
            const result = StaticBearerProvider.validateStaticBearerConfig({ 
                config: 'not an object' 
            })
            
            expect(result.status).toBe(false)
            expect(result.messages).toContain('StaticBearer config must be a valid object')
        })
    })

    describe('provider metadata methods', () => {
        test('getProviderName returns correct name', () => {
            expect(provider.getProviderName()).toBe('staticBearer')
        })

        test('getDisplayName returns correct display name', () => {
            expect(provider.getDisplayName()).toBe('Static Bearer Token')
        })

        test('getSupportedFlows returns empty array', () => {
            expect(StaticBearerProvider.getSupportedFlows()).toEqual([])
        })

        test('getDefaultScopes returns empty string', () => {
            expect(StaticBearerProvider.getDefaultScopes()).toBe('')
        })

        test('getAuthType returns correct authType', () => {
            expect(StaticBearerProvider.getAuthType()).toBe('staticBearer')
        })
    })
})