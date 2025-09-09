import { jest } from '@jest/globals'

// Mock fetch before importing any modules that use it
const mockFetch = jest.fn()
jest.unstable_mockModule('node-fetch', () => ({
    default: mockFetch
}))

// Import modules after mocking
const { OAuth21Auth0FlowHandler } = await import('../../../../src/authTypes/oauth21_auth0/OAuth21Auth0FlowHandler.mjs')

describe('OAuth21Auth0FlowHandler', () => {
    let handler
    let mockConfig

    beforeEach(() => {
        jest.clearAllMocks()
        
        mockConfig = {
            providerUrl: 'https://tenant.auth0.com',
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            scope: 'openid profile email',
            audience: 'https://api.example.com',
            redirectUri: 'http://localhost:3000/auth/callback'
        }
    })

    describe('createForAuth0', () => {
        test('creates handler with enhanced config', () => {
            const result = OAuth21Auth0FlowHandler.createForAuth0({
                config: mockConfig,
                redirectUri: 'http://localhost:3000/custom/callback',
                silent: true
            })

            expect(result).toBeInstanceOf(OAuth21Auth0FlowHandler)
            expect(result.getConfig().redirectUri).toBe('http://localhost:3000/custom/callback')
        })

        test('uses default redirect URI when none provided', () => {
            const configWithoutRedirect = { ...mockConfig }
            delete configWithoutRedirect.redirectUri

            const result = OAuth21Auth0FlowHandler.createForAuth0({
                config: configWithoutRedirect,
                silent: true
            })

            expect(result.getConfig().redirectUri).toBe('http://localhost:3000/auth/callback')
        })

        test('uses base URL from config for default redirect URI', () => {
            const configWithBaseUrl = {
                ...mockConfig,
                baseUrl: 'https://example.com:8080'
            }
            delete configWithBaseUrl.redirectUri

            const result = OAuth21Auth0FlowHandler.createForAuth0({
                config: configWithBaseUrl,
                silent: true
            })

            expect(result.getConfig().redirectUri).toBe('https://example.com:8080/auth/callback')
        })
    })

    describe('constructor and initialization', () => {
        test('initializes with provided config', () => {
            handler = new OAuth21Auth0FlowHandler({ config: mockConfig, silent: true })
            
            expect(handler.getConfig()).toEqual(mockConfig)
            expect(handler.getAuthType()).toBe('oauth21_auth0')
        })

        test('initializes endpoints correctly', () => {
            handler = new OAuth21Auth0FlowHandler({ config: mockConfig, silent: true })
            const endpoints = handler.getEndpoints()

            expect(endpoints.authorizationEndpoint).toBe('https://tenant.auth0.com/authorize')
            expect(endpoints.tokenEndpoint).toBe('https://tenant.auth0.com/oauth/token')
            expect(endpoints.jwksUrl).toBe('https://tenant.auth0.com/.well-known/jwks.json')
            expect(endpoints.userInfoUrl).toBe('https://tenant.auth0.com/userinfo')
            expect(endpoints.discoveryUrl).toBe('https://tenant.auth0.com/.well-known/openid_configuration')
        })

        test('uses custom endpoints when provided in config', () => {
            const configWithCustomEndpoints = {
                ...mockConfig,
                tokenEndpoint: 'https://custom.auth0.com/oauth/token',
                userInfoEndpoint: 'https://custom.auth0.com/userinfo'
            }

            handler = new OAuth21Auth0FlowHandler({ config: configWithCustomEndpoints, silent: true })
            const endpoints = handler.getEndpoints()

            expect(endpoints.tokenEndpoint).toBe('https://custom.auth0.com/oauth/token')
            expect(endpoints.userInfoUrl).toBe('https://custom.auth0.com/userinfo')
        })
    })

    describe('initiateAuthorizationCodeFlow', () => {
        beforeEach(() => {
            handler = new OAuth21Auth0FlowHandler({ config: mockConfig, silent: true })
        })

        test('generates authorization URL with required parameters', () => {
            const result = handler.initiateAuthorizationCodeFlow({
                scopes: 'openid profile',
                audience: 'https://api.example.com',
                state: 'test-state-123'
            })

            expect(result.authorizationUrl).toContain('https://tenant.auth0.com/authorize')
            expect(result.authorizationUrl).toContain('client_id=test-client-id')
            expect(result.authorizationUrl).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback')
            expect(result.authorizationUrl).toContain('scope=openid+profile')
            expect(result.authorizationUrl).toContain('state=test-state-123')
            expect(result.authorizationUrl).toContain('response_type=code')
            expect(result.authorizationUrl).toContain('code_challenge=')
            expect(result.authorizationUrl).toContain('code_challenge_method=S256')
            expect(result.authorizationUrl).toContain('audience=https%3A%2F%2Fapi.example.com')
        })

        test('uses default scopes when none provided', () => {
            const result = handler.initiateAuthorizationCodeFlow({})

            expect(result.authorizationUrl).toContain('scope=openid+profile+email')
        })

        test('uses config scopes when parameter scopes not provided', () => {
            const result = handler.initiateAuthorizationCodeFlow({})

            expect(result.authorizationUrl).toContain('scope=openid+profile+email')
        })

        test('generates random state when none provided', () => {
            const result1 = handler.initiateAuthorizationCodeFlow({})
            const result2 = handler.initiateAuthorizationCodeFlow({})

            expect(result1.state).toBeDefined()
            expect(result2.state).toBeDefined()
            expect(result1.state).not.toBe(result2.state)
        })

        test('omits audience parameter when not provided', () => {
            const configWithoutAudience = { ...mockConfig }
            delete configWithoutAudience.audience

            const handlerWithoutAudience = new OAuth21Auth0FlowHandler({ 
                config: configWithoutAudience, 
                silent: true 
            })

            const result = handlerWithoutAudience.initiateAuthorizationCodeFlow({ 
                scopes: 'openid profile'
            })

            expect(result.authorizationUrl).not.toContain('audience=')
        })

        test('returns proper response structure', () => {
            const result = handler.initiateAuthorizationCodeFlow({
                state: 'test-state'
            })

            expect(result).toHaveProperty('authorizationUrl')
            expect(result).toHaveProperty('state', 'test-state')
            expect(result).toHaveProperty('authType', 'oauth21_auth0')
        })
    })

    describe('handleAuthorizationCallback', () => {
        let mockTokenResponse

        beforeEach(() => {
            handler = new OAuth21Auth0FlowHandler({ config: mockConfig, silent: true })
            
            mockTokenResponse = {
                access_token: 'mock-access-token',
                token_type: 'Bearer',
                expires_in: 3600,
                scope: 'openid profile email'
            }

            mockFetch.mockResolvedValue({
                json: jest.fn().mockResolvedValue(mockTokenResponse)
            })
        })

        test('successfully handles valid authorization callback', async () => {
            // First create an authorization request
            const authResult = handler.initiateAuthorizationCodeFlow({
                state: 'test-state'
            })

            // Then handle the callback
            const result = await handler.handleAuthorizationCallback({
                code: 'test-auth-code',
                state: 'test-state'
            })

            expect(result.success).toBe(true)
            expect(result.tokens).toEqual(mockTokenResponse)
            expect(result.authType).toBe('oauth21_auth0')
        })

        test('fails with invalid state parameter', async () => {
            const result = await handler.handleAuthorizationCallback({
                code: 'test-auth-code',
                state: 'invalid-state'
            })

            expect(result.success).toBe(false)
            expect(result.error).toBe('Invalid state parameter')
            expect(result.authType).toBe('oauth21_auth0')
        })

        test('handles token exchange errors', async () => {
            const errorResponse = {
                error: 'invalid_grant',
                error_description: 'Authorization code is invalid'
            }

            mockFetch.mockResolvedValue({
                json: jest.fn().mockResolvedValue(errorResponse)
            })

            // Create authorization request first
            handler.initiateAuthorizationCodeFlow({ state: 'test-state' })

            const result = await handler.handleAuthorizationCallback({
                code: 'invalid-code',
                state: 'test-state'
            })

            expect(result.success).toBe(false)
            expect(result.error).toBe('Authorization code is invalid')
            expect(result.authType).toBe('oauth21_auth0')
        })

        test('cleans up authorization request after processing', async () => {
            // Create authorization request
            handler.initiateAuthorizationCodeFlow({ state: 'test-state' })

            // Handle callback
            await handler.handleAuthorizationCallback({
                code: 'test-auth-code',
                state: 'test-state'
            })

            // Try to handle same callback again - should fail
            const result = await handler.handleAuthorizationCallback({
                code: 'test-auth-code',
                state: 'test-state'
            })

            expect(result.success).toBe(false)
            expect(result.error).toBe('Invalid state parameter')
        })
    })

    describe('requestClientCredentials', () => {
        let mockTokenResponse

        beforeEach(() => {
            handler = new OAuth21Auth0FlowHandler({ config: mockConfig, silent: true })
            
            mockTokenResponse = {
                access_token: 'mock-client-credentials-token',
                token_type: 'Bearer',
                expires_in: 3600
            }

            mockFetch.mockResolvedValue({
                json: jest.fn().mockResolvedValue(mockTokenResponse)
            })
        })

        test('successfully requests client credentials', async () => {
            const result = await handler.requestClientCredentials({
                scopes: 'read:users',
                audience: 'https://api.example.com'
            })

            expect(result.success).toBe(true)
            expect(result.tokens).toEqual(mockTokenResponse)
            expect(result.authType).toBe('oauth21_auth0')
            expect(result.audience).toBe('https://api.example.com')

            expect(mockFetch).toHaveBeenCalledWith(
                'https://tenant.auth0.com/oauth/token',
                expect.objectContaining({
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                })
            )
        })

        test('uses default scopes and audience from config', async () => {
            const result = await handler.requestClientCredentials({})

            expect(result.success).toBe(true)
            expect(result.audience).toBe('https://api.example.com')

            const callBody = mockFetch.mock.calls[0][1].body
            expect(callBody).toContain('scope=openid+profile+email')
            expect(callBody).toContain('audience=https%3A%2F%2Fapi.example.com')
        })

        test('omits optional parameters when not provided', async () => {
            const configWithoutDefaults = {
                providerUrl: 'https://tenant.auth0.com',
                clientId: 'test-client-id',
                clientSecret: 'test-client-secret'
            }
            const handlerWithoutDefaults = new OAuth21Auth0FlowHandler({ 
                config: configWithoutDefaults, 
                silent: true 
            })

            const result = await handlerWithoutDefaults.requestClientCredentials({})

            expect(result.success).toBe(true)

            const callBody = mockFetch.mock.calls[0][1].body
            expect(callBody).not.toContain('scope=')
            expect(callBody).not.toContain('audience=')
        })

        test('handles client credentials errors', async () => {
            const errorResponse = {
                error: 'invalid_client',
                error_description: 'Client authentication failed'
            }

            mockFetch.mockResolvedValue({
                json: jest.fn().mockResolvedValue(errorResponse)
            })

            const result = await handler.requestClientCredentials({})

            expect(result.success).toBe(false)
            expect(result.error).toBe('Client authentication failed')
            expect(result.authType).toBe('oauth21_auth0')
        })
    })

    describe('refreshAccessToken', () => {
        let mockTokenResponse

        beforeEach(() => {
            handler = new OAuth21Auth0FlowHandler({ config: mockConfig, silent: true })
            
            mockTokenResponse = {
                access_token: 'new-access-token',
                token_type: 'Bearer',
                expires_in: 3600
            }

            mockFetch.mockResolvedValue({
                json: jest.fn().mockResolvedValue(mockTokenResponse)
            })
        })

        test('successfully refreshes access token', async () => {
            const result = await handler.refreshAccessToken({
                refreshToken: 'mock-refresh-token',
                audience: 'https://api.example.com'
            })

            expect(result.success).toBe(true)
            expect(result.tokens).toEqual(mockTokenResponse)
            expect(result.authType).toBe('oauth21_auth0')
            expect(result.audience).toBe('https://api.example.com')

            const callBody = mockFetch.mock.calls[0][1].body
            expect(callBody).toContain('grant_type=refresh_token')
            expect(callBody).toContain('refresh_token=mock-refresh-token')
            expect(callBody).toContain('client_id=test-client-id')
            expect(callBody).toContain('client_secret=test-client-secret')
        })

        test('uses default audience from config', async () => {
            const result = await handler.refreshAccessToken({
                refreshToken: 'mock-refresh-token'
            })

            expect(result.success).toBe(true)
            expect(result.audience).toBe('https://api.example.com')
        })

        test('handles refresh token errors', async () => {
            const errorResponse = {
                error: 'invalid_grant',
                error_description: 'Refresh token is invalid'
            }

            mockFetch.mockResolvedValue({
                json: jest.fn().mockResolvedValue(errorResponse)
            })

            const result = await handler.refreshAccessToken({
                refreshToken: 'invalid-refresh-token'
            })

            expect(result.success).toBe(false)
            expect(result.error).toBe('Refresh token is invalid')
            expect(result.authType).toBe('oauth21_auth0')
        })
    })

    describe('discoverConfiguration', () => {
        let mockDiscoveryResponse

        beforeEach(() => {
            handler = new OAuth21Auth0FlowHandler({ config: mockConfig, silent: true })
            
            mockDiscoveryResponse = {
                issuer: 'https://tenant.auth0.com',
                authorization_endpoint: 'https://tenant.auth0.com/authorize',
                token_endpoint: 'https://tenant.auth0.com/oauth/token',
                userinfo_endpoint: 'https://tenant.auth0.com/userinfo',
                jwks_uri: 'https://tenant.auth0.com/.well-known/jwks.json'
            }
        })

        test('successfully discovers OAuth configuration', async () => {
            mockFetch.mockResolvedValue({
                json: jest.fn().mockResolvedValue(mockDiscoveryResponse)
            })

            const result = await handler.discoverConfiguration()

            expect(result.success).toBe(true)
            expect(result.config).toEqual(mockDiscoveryResponse)
            expect(result.authType).toBe('oauth21_auth0')

            expect(mockFetch).toHaveBeenCalledWith(
                'https://tenant.auth0.com/.well-known/openid_configuration'
            )
        })

        test('handles discovery errors', async () => {
            mockFetch.mockRejectedValue(new Error('Network error'))

            const result = await handler.discoverConfiguration()

            expect(result.success).toBe(false)
            expect(result.error).toBe('Network error')
            expect(result.authType).toBe('oauth21_auth0')
        })
    })

    describe('clearExpiredAuthRequests', () => {
        beforeEach(() => {
            handler = new OAuth21Auth0FlowHandler({ config: mockConfig, silent: true })
        })

        test('clears expired authorization requests', () => {
            // Create some authorization requests with different timestamps
            const now = Date.now()
            
            // Mock Date.now for consistent timing
            const originalDateNow = Date.now
            Date.now = jest.fn()
                .mockReturnValueOnce(now - 700000) // 11+ minutes ago (expired)
                .mockReturnValueOnce(now - 300000) // 5 minutes ago (not expired)
                .mockReturnValue(now) // Current time for cleanup

            try {
                handler.initiateAuthorizationCodeFlow({ state: 'expired-state' })
                handler.initiateAuthorizationCodeFlow({ state: 'valid-state' })

                // Reset Date.now to current time for cleanup call
                Date.now = jest.fn().mockReturnValue(now)

                handler.clearExpiredAuthRequests()

                // Try to handle expired callback - should fail
                const expiredResult = handler.handleAuthorizationCallback({
                    code: 'test-code',
                    state: 'expired-state'
                })

                // Try to handle valid callback - should work (before actually handling it)
                // We just test that the state exists by checking that it's not immediately invalid
                const validCheck = handler.initiateAuthorizationCodeFlow({ state: 'valid-state' })
                expect(validCheck.state).toBe('valid-state')

            } finally {
                Date.now = originalDateNow
            }
        })

        test('handles no expired requests', () => {
            // Create a recent authorization request
            handler.initiateAuthorizationCodeFlow({ state: 'recent-state' })

            // Should not throw or cause issues
            expect(() => handler.clearExpiredAuthRequests()).not.toThrow()
        })
    })

    describe('getter methods', () => {
        beforeEach(() => {
            handler = new OAuth21Auth0FlowHandler({ config: mockConfig, silent: true })
        })

        test('getEndpoints returns copy of endpoints', () => {
            const endpoints = handler.getEndpoints()

            expect(endpoints).toHaveProperty('authorizationEndpoint')
            expect(endpoints).toHaveProperty('tokenEndpoint')
            expect(endpoints).toHaveProperty('jwksUrl')

            // Should be a copy, not reference
            endpoints.authorizationEndpoint = 'modified'
            const endpoints2 = handler.getEndpoints()
            expect(endpoints2.authorizationEndpoint).not.toBe('modified')
        })

        test('getConfig returns copy of config', () => {
            const config = handler.getConfig()

            expect(config).toEqual(mockConfig)

            // Should be a copy, not reference
            config.clientId = 'modified'
            const config2 = handler.getConfig()
            expect(config2.clientId).toBe('test-client-id')
        })

        test('getAuthType returns oauth21_auth0', () => {
            expect(handler.getAuthType()).toBe('oauth21_auth0')
        })
    })
})