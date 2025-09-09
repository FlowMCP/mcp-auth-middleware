import { jest } from '@jest/globals'

// Mock external dependencies
const mockJwt = {
    verify: jest.fn()
}

const mockJwksClient = jest.fn()

jest.unstable_mockModule('jsonwebtoken', () => ({
    default: mockJwt
}))
jest.unstable_mockModule('jwks-client', () => ({
    default: mockJwksClient
}))

// Import after mocking
const { OAuth21Auth0TokenValidator } = await import('../../../../src/authTypes/oauth21_auth0/OAuth21Auth0TokenValidator.mjs')

describe('OAuth21Auth0TokenValidator', () => {
    let validator
    let mockConfig
    let mockJwksClientInstance

    beforeEach(() => {
        jest.clearAllMocks()
        
        mockConfig = {
            providerUrl: 'https://tenant.auth0.com',
            clientId: 'test-client-id',
            audience: 'https://api.example.com'
        }

        // Mock JWKS client instance
        mockJwksClientInstance = {
            getSigningKey: jest.fn()
        }
        mockJwksClient.mockReturnValue(mockJwksClientInstance)
    })

    describe('constructor and initialization', () => {
        test('creates validator with config and initializes JWKS client', () => {
            validator = new OAuth21Auth0TokenValidator({ config: mockConfig, silent: true })

            expect(validator).toBeInstanceOf(OAuth21Auth0TokenValidator)
            expect(mockJwksClient).toHaveBeenCalledWith({
                jwksUri: 'https://tenant.auth0.com/.well-known/jwks.json',
                timeout: 30000
            })
        })

        test('creates validator with default silent false', () => {
            validator = new OAuth21Auth0TokenValidator({ config: mockConfig })

            expect(validator).toBeInstanceOf(OAuth21Auth0TokenValidator)
        })

        test('initializes empty validation cache', () => {
            validator = new OAuth21Auth0TokenValidator({ config: mockConfig, silent: true })

            // Test cache by clearing it (should not throw)
            validator.clearValidationCache()
        })
    })

    describe('createForAuth0 static method', () => {
        test('creates validator instance via static method', () => {
            const result = OAuth21Auth0TokenValidator.createForAuth0({ config: mockConfig, silent: true })

            expect(result).toBeInstanceOf(OAuth21Auth0TokenValidator)
        })

        test('passes config and silent option correctly', () => {
            const result = OAuth21Auth0TokenValidator.createForAuth0({ config: mockConfig, silent: false })

            expect(result.getConfig()).toEqual(mockConfig)
        })
    })

    describe('validate method', () => {
        let mockToken
        let mockDecoded

        beforeEach(() => {
            validator = new OAuth21Auth0TokenValidator({ config: mockConfig, silent: true })
            mockToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.token'
            mockDecoded = {
                sub: 'user123',
                aud: 'https://api.example.com',
                iss: 'https://tenant.auth0.com/',
                exp: Math.floor(Date.now() / 1000) + 3600,
                scope: 'openid profile email'
            }
        })

        test('successfully validates valid token', async () => {
            // Mock successful JWT verification
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, mockDecoded)
            })

            const result = await validator.validate({ token: mockToken })

            expect(result).toEqual({
                isValid: true,
                error: null,
                decoded: mockDecoded,
                authType: 'oauth21_auth0'
            })
        })

        test('handles invalid token with error', async () => {
            const mockError = new Error('Token expired')
            
            // Mock failed JWT verification
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(mockError)
            })

            const result = await validator.validate({ token: mockToken })

            expect(result).toEqual({
                isValid: false,
                error: 'Token expired',
                decoded: null,
                authType: 'oauth21_auth0'
            })
        })

        test('uses correct JWT verification options', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, mockDecoded)
            })

            await validator.validate({ token: mockToken })

            expect(mockJwt.verify).toHaveBeenCalledWith(
                mockToken,
                expect.any(Function), // Key function
                {
                    issuer: 'https://tenant.auth0.com/',
                    audience: 'https://api.example.com',
                    algorithms: ['RS256']
                },
                expect.any(Function) // Callback
            )
        })

        test('falls back to clientId when no audience specified', async () => {
            const configWithoutAudience = { ...mockConfig }
            delete configWithoutAudience.audience
            
            validator = new OAuth21Auth0TokenValidator({ config: configWithoutAudience, silent: true })
            
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, mockDecoded)
            })

            await validator.validate({ token: mockToken })

            expect(mockJwt.verify).toHaveBeenCalledWith(
                mockToken,
                expect.any(Function),
                expect.objectContaining({
                    audience: 'test-client-id' // Falls back to clientId
                }),
                expect.any(Function)
            )
        })

        test('caches successful validation results', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, mockDecoded)
            })

            // First validation
            const result1 = await validator.validate({ token: mockToken })
            expect(mockJwt.verify).toHaveBeenCalledTimes(1)

            // Second validation should use cache
            const result2 = await validator.validate({ token: mockToken })
            expect(mockJwt.verify).toHaveBeenCalledTimes(1) // Still only called once

            expect(result1).toEqual(result2)
        })

        test('does not cache failed validation results', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(new Error('Invalid token'))
            })

            // First validation
            await validator.validate({ token: mockToken })
            expect(mockJwt.verify).toHaveBeenCalledTimes(1)

            // Second validation should not use cache for failed results
            await validator.validate({ token: mockToken })
            expect(mockJwt.verify).toHaveBeenCalledTimes(2)
        })
    })

    describe('validateWithAudienceBinding method', () => {
        let mockToken
        let mockDecoded

        beforeEach(() => {
            validator = new OAuth21Auth0TokenValidator({ config: mockConfig, silent: true })
            mockToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.token'
            mockDecoded = {
                sub: 'user123',
                aud: 'https://api.example.com',
                iss: 'https://tenant.auth0.com/',
                scope: 'openid profile email'
            }
        })

        test('validates token with matching audience', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, mockDecoded)
            })

            const result = await validator.validateWithAudienceBinding({ 
                token: mockToken, 
                audience: 'https://api.example.com' 
            })

            expect(result.isValid).toBe(true)
            expect(result.audienceBinding.isValidAudience).toBe(true)
            expect(result.audienceBinding.tokenAudience).toEqual(['https://api.example.com'])
            expect(result.audienceBinding.requiredAudience).toBe('https://api.example.com')
        })

        test('validates token with mismatched audience', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, mockDecoded)
            })

            const result = await validator.validateWithAudienceBinding({ 
                token: mockToken, 
                audience: 'https://different-api.example.com' 
            })

            expect(result.isValid).toBe(true)
            expect(result.audienceBinding.isValidAudience).toBe(false)
            expect(result.audienceBinding.message).toContain('audience mismatch')
        })

        test('handles array audience in token', async () => {
            const decodedWithArrayAudience = {
                ...mockDecoded,
                aud: ['https://api.example.com', 'https://other-api.example.com']
            }
            
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, decodedWithArrayAudience)
            })

            const result = await validator.validateWithAudienceBinding({ 
                token: mockToken, 
                audience: 'https://other-api.example.com' 
            })

            expect(result.audienceBinding.isValidAudience).toBe(true)
            expect(result.audienceBinding.tokenAudience).toHaveLength(2)
        })

        test('skips audience validation when no audience specified', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, mockDecoded)
            })

            const result = await validator.validateWithAudienceBinding({ 
                token: mockToken 
            })

            expect(result.audienceBinding.isValidAudience).toBe(true)
            expect(result.audienceBinding.message).toContain('No audience specified')
        })

        test('returns invalid result when base token validation fails', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(new Error('Invalid token'))
            })

            const result = await validator.validateWithAudienceBinding({ 
                token: mockToken, 
                audience: 'https://api.example.com' 
            })

            expect(result.isValid).toBe(false)
            expect(result.error).toBe('Invalid token')
            expect(result.audienceBinding).toBeUndefined()
        })
    })

    describe('validateScopes method', () => {
        let mockToken
        let mockDecoded

        beforeEach(() => {
            validator = new OAuth21Auth0TokenValidator({ config: mockConfig, silent: true })
            mockToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.token'
            mockDecoded = {
                sub: 'user123',
                aud: 'https://api.example.com',
                scope: 'openid profile email read:users'
            }
        })

        test('validates token with all required scopes present', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, mockDecoded)
            })

            const result = await validator.validateScopes({ 
                token: mockToken, 
                requiredScopes: ['openid', 'profile', 'read:users'] 
            })

            expect(result.hasRequiredScopes).toBe(true)
            expect(result.missingScopes).toHaveLength(0)
            expect(result.availableScopes).toEqual(['openid', 'profile', 'email', 'read:users'])
        })

        test('identifies missing scopes', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, mockDecoded)
            })

            const result = await validator.validateScopes({ 
                token: mockToken, 
                requiredScopes: ['openid', 'profile', 'write:users', 'admin'] 
            })

            expect(result.hasRequiredScopes).toBe(false)
            expect(result.missingScopes).toEqual(['write:users', 'admin'])
            expect(result.availableScopes).toEqual(['openid', 'profile', 'email', 'read:users'])
        })

        test('handles scopes in scp claim (array format)', async () => {
            const decodedWithScpArray = {
                ...mockDecoded,
                scp: ['openid', 'profile', 'email', 'read:users']
            }
            delete decodedWithScpArray.scope
            
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, decodedWithScpArray)
            })

            const result = await validator.validateScopes({ 
                token: mockToken, 
                requiredScopes: ['openid', 'read:users'] 
            })

            expect(result.hasRequiredScopes).toBe(true)
            expect(result.availableScopes).toEqual(['openid', 'profile', 'email', 'read:users'])
        })

        test('handles token with no scope claims', async () => {
            const decodedWithoutScopes = { ...mockDecoded }
            delete decodedWithoutScopes.scope
            
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(null, decodedWithoutScopes)
            })

            const result = await validator.validateScopes({ 
                token: mockToken, 
                requiredScopes: ['openid', 'profile'] 
            })

            expect(result.hasRequiredScopes).toBe(false)
            expect(result.missingScopes).toEqual(['openid', 'profile'])
            expect(result.availableScopes).toEqual([])
        })

        test('returns all missing scopes when token validation fails', async () => {
            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                callback(new Error('Invalid token'))
            })

            const requiredScopes = ['openid', 'profile', 'read:users']
            const result = await validator.validateScopes({ 
                token: mockToken, 
                requiredScopes 
            })

            expect(result.hasRequiredScopes).toBe(false)
            expect(result.missingScopes).toEqual(requiredScopes)
            expect(result.validationResult.isValid).toBe(false)
        })
    })

    describe('JWKS key retrieval', () => {
        let mockToken

        beforeEach(() => {
            validator = new OAuth21Auth0TokenValidator({ config: mockConfig, silent: true })
            mockToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.token'
        })

        test('retrieves signing key successfully', async () => {
            const mockKey = { publicKey: 'mock-public-key' }
            
            mockJwksClientInstance.getSigningKey.mockImplementation((kid, callback) => {
                callback(null, mockKey)
            })

            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                // Test the key function
                keyFunc({ kid: 'test-kid' }, (err, key) => {
                    expect(err).toBeNull()
                    expect(key).toBe('mock-public-key')
                })
                callback(null, { sub: 'test' })
            })

            await validator.validate({ token: mockToken })
        })

        test('handles signing key retrieval error', async () => {
            const mockError = new Error('Key not found')
            
            mockJwksClientInstance.getSigningKey.mockImplementation((kid, callback) => {
                callback(mockError)
            })

            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                // Test the key function with error
                keyFunc({ kid: 'invalid-kid' }, (err, key) => {
                    expect(err).toBe(mockError)
                })
                callback(mockError)
            })

            const result = await validator.validate({ token: mockToken })
            expect(result.isValid).toBe(false)
        })

        test('uses RSA public key when regular public key not available', async () => {
            const mockKey = { rsaPublicKey: 'mock-rsa-public-key' }
            
            mockJwksClientInstance.getSigningKey.mockImplementation((kid, callback) => {
                callback(null, mockKey)
            })

            mockJwt.verify.mockImplementation((token, keyFunc, options, callback) => {
                keyFunc({ kid: 'test-kid' }, (err, key) => {
                    expect(key).toBe('mock-rsa-public-key')
                })
                callback(null, { sub: 'test' })
            })

            await validator.validate({ token: mockToken })
        })
    })

    describe('cache management', () => {
        beforeEach(() => {
            validator = new OAuth21Auth0TokenValidator({ config: mockConfig, silent: true })
        })

        test('clears validation cache', () => {
            // This tests that clearValidationCache executes without error
            validator.clearValidationCache()
            
            // Should be able to call multiple times
            validator.clearValidationCache()
        })
    })

    describe('getter methods', () => {
        beforeEach(() => {
            validator = new OAuth21Auth0TokenValidator({ config: mockConfig, silent: true })
        })

        test('getAuthType returns correct auth type', () => {
            const result = validator.getAuthType()

            expect(result).toBe('oauth21_auth0')
        })

        test('getConfig returns copy of config', () => {
            const result = validator.getConfig()

            expect(result).toEqual(mockConfig)
            expect(result).not.toBe(mockConfig) // Should be a copy, not the same object
        })
    })
})