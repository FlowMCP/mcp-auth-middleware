import { StaticBearerTokenValidator } from '../../../../src/authTypes/staticBearer/StaticBearerTokenValidator.mjs'

describe('StaticBearerTokenValidator', () => {
    let validator
    const mockConfig = {
        token: 'test-token-123456'
    }

    beforeEach(() => {
        validator = new StaticBearerTokenValidator({ config: mockConfig, silent: true })
    })

    describe('constructor', () => {
        test('creates validator with config', () => {
            expect(validator).toBeInstanceOf(StaticBearerTokenValidator)
        })

        test('accepts silent parameter', () => {
            const silentValidator = new StaticBearerTokenValidator({ config: mockConfig, silent: true })
            const verboseValidator = new StaticBearerTokenValidator({ config: mockConfig, silent: false })
            
            expect(silentValidator).toBeInstanceOf(StaticBearerTokenValidator)
            expect(verboseValidator).toBeInstanceOf(StaticBearerTokenValidator)
        })

        test('trims configured token', () => {
            const configWithSpaces = { token: '  test-token-123456  ' }
            const trimValidator = new StaticBearerTokenValidator({ config: configWithSpaces, silent: true })
            
            expect(trimValidator).toBeInstanceOf(StaticBearerTokenValidator)
        })
    })

    describe('static createForStaticBearer', () => {
        test('creates validator instance', () => {
            const staticValidator = StaticBearerTokenValidator.createForStaticBearer({ 
                config: mockConfig, 
                silent: true 
            })
            
            expect(staticValidator).toBeInstanceOf(StaticBearerTokenValidator)
        })
    })

    describe('validate', () => {
        test('validates correct token without Bearer prefix', async () => {
            const result = await validator.validate({ token: 'test-token-123456' })
            
            expect(result.isValid).toBe(true)
            expect(result.error).toBeNull()
            expect(result.decoded).toEqual({
                token: 'test-token-123456',
                authType: 'staticBearer'
            })
            expect(result.authType).toBe('staticBearer')
        })

        test('validates correct token with Bearer prefix', async () => {
            const result = await validator.validate({ token: 'Bearer test-token-123456' })
            
            expect(result.isValid).toBe(true)
            expect(result.error).toBeNull()
            expect(result.decoded).toEqual({
                token: 'test-token-123456',
                authType: 'staticBearer'
            })
            expect(result.authType).toBe('staticBearer')
        })

        test('validates correct token with bearer prefix (lowercase)', async () => {
            const result = await validator.validate({ token: 'bearer test-token-123456' })
            
            expect(result.isValid).toBe(true)
            expect(result.error).toBeNull()
            expect(result.decoded.token).toBe('test-token-123456')
        })

        test('validates correct token with extra spaces', async () => {
            const result = await validator.validate({ token: 'Bearer   test-token-123456   ' })
            
            expect(result.isValid).toBe(true)
            expect(result.decoded.token).toBe('test-token-123456')
        })

        test('rejects incorrect token', async () => {
            const result = await validator.validate({ token: 'Bearer wrong-token' })
            
            expect(result.isValid).toBe(false)
            expect(result.error).toBe('Invalid bearer token')
            expect(result.decoded).toBeNull()
            expect(result.authType).toBe('staticBearer')
        })

        test('rejects empty token', async () => {
            const result = await validator.validate({ token: '' })
            
            expect(result.isValid).toBe(false)
            expect(result.error).toBe('Invalid bearer token')
            expect(result.decoded).toBeNull()
        })

        test('rejects token with only Bearer prefix', async () => {
            const result = await validator.validate({ token: 'Bearer' })
            
            expect(result.isValid).toBe(false)
            expect(result.error).toBe('Invalid bearer token')
        })

        test('rejects token with only spaces after Bearer', async () => {
            const result = await validator.validate({ token: 'Bearer   ' })
            
            expect(result.isValid).toBe(false)
            expect(result.error).toBe('Invalid bearer token')
        })

        test('handles case-insensitive Bearer extraction', async () => {
            const testCases = [
                'BEARER test-token-123456',
                'Bearer test-token-123456',
                'bearer test-token-123456',
                'BeArEr test-token-123456'
            ]

            for (const testCase of testCases) {
                const result = await validator.validate({ token: testCase })
                expect(result.isValid).toBe(true)
                expect(result.decoded.token).toBe('test-token-123456')
            }
        })

        test('preserves token case after extraction', async () => {
            const upperCaseValidator = new StaticBearerTokenValidator({ 
                config: { token: 'TOKEN123ABC' }, 
                silent: true 
            })
            
            const result = await upperCaseValidator.validate({ token: 'Bearer TOKEN123ABC' })
            
            expect(result.isValid).toBe(true)
            expect(result.decoded.token).toBe('TOKEN123ABC')
        })
    })

    describe('validateScopes', () => {
        test('always returns successful scope validation', async () => {
            const result = await validator.validateScopes({ 
                token: 'Bearer test-token-123456',
                requiredScopes: ['api:read', 'api:write']
            })
            
            expect(result.hasRequiredScopes).toBe(true)
            expect(result.missingScopes).toEqual([])
            expect(result.availableScopes).toEqual([])
        })

        test('validates scopes without requiredScopes parameter', async () => {
            const result = await validator.validateScopes({ 
                token: 'Bearer test-token-123456'
            })
            
            expect(result.hasRequiredScopes).toBe(true)
            expect(result.missingScopes).toEqual([])
            expect(result.availableScopes).toEqual([])
        })

        test('includes token validation result', async () => {
            const result = await validator.validateScopes({ 
                token: 'Bearer test-token-123456'
            })
            
            expect(result.validationResult).toBeDefined()
            expect(result.validationResult.isValid).toBe(true)
            expect(result.validationResult.authType).toBe('staticBearer')
        })

        test('includes failed token validation in scope result', async () => {
            const result = await validator.validateScopes({ 
                token: 'Bearer wrong-token'
            })
            
            expect(result.validationResult.isValid).toBe(false)
            expect(result.validationResult.error).toBe('Invalid bearer token')
        })
    })

    describe('utility methods', () => {
        test('clearValidationCache does not throw', () => {
            expect(() => validator.clearValidationCache()).not.toThrow()
        })

        test('getAuthType returns correct authType', () => {
            expect(validator.getAuthType()).toBe('staticBearer')
        })

        test('getConfig returns sanitized config', () => {
            const config = validator.getConfig()
            
            expect(config.authType).toBe('staticBearer')
            expect(config.tokenLength).toBe(mockConfig.token.length)
            expect(config.token).toBeUndefined() // Should not expose actual token
        })
    })

    describe('edge cases', () => {
        test('handles very long tokens', async () => {
            const longToken = 'a'.repeat(1000)
            const longTokenValidator = new StaticBearerTokenValidator({ 
                config: { token: longToken }, 
                silent: true 
            })
            
            const result = await longTokenValidator.validate({ token: `Bearer ${longToken}` })
            
            expect(result.isValid).toBe(true)
            expect(result.decoded.token).toBe(longToken)
        })

        test('handles tokens with special characters', async () => {
            const specialToken = 'token-with_special.chars+and=symbols'
            const specialTokenValidator = new StaticBearerTokenValidator({ 
                config: { token: specialToken }, 
                silent: true 
            })
            
            const result = await specialTokenValidator.validate({ token: `Bearer ${specialToken}` })
            
            expect(result.isValid).toBe(true)
            expect(result.decoded.token).toBe(specialToken)
        })

        test('handles tokens that contain the word Bearer', async () => {
            const bearerContainingToken = 'my-bearer-token-contains-bearer-word'
            const bearerValidator = new StaticBearerTokenValidator({ 
                config: { token: bearerContainingToken }, 
                silent: true 
            })
            
            const result = await bearerValidator.validate({ token: `Bearer ${bearerContainingToken}` })
            
            expect(result.isValid).toBe(true)
            expect(result.decoded.token).toBe(bearerContainingToken)
        })
    })
})