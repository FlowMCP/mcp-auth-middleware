import { jest } from '@jest/globals'
import request from 'supertest'
import express from 'express'

// Mock external dependencies
jest.unstable_mockModule('../../../src/core/AuthTypeFactory.mjs', () => ({
    AuthTypeFactory: {
        createAuthHandler: jest.fn()
    }
}))

jest.unstable_mockModule('../../../src/helpers/TokenValidator.mjs', () => ({
    TokenValidator: {
        createForMultiRealm: jest.fn()
    }
}))

jest.unstable_mockModule('../../../src/helpers/OAuthFlowHandler.mjs', () => ({
    OAuthFlowHandler: {
        createForMultiRealm: jest.fn()
    }
}))

jest.unstable_mockModule('../../../src/task/Validation.mjs', () => ({
    Validation: {
        validationCreate: jest.fn()
    }
}))

// Import after mocking
const { McpAuthMiddleware } = await import('../../../src/task/McpAuthMiddleware.mjs')
const { AuthTypeFactory } = await import('../../../src/core/AuthTypeFactory.mjs')
const { TokenValidator } = await import('../../../src/helpers/TokenValidator.mjs')
const { OAuthFlowHandler } = await import('../../../src/helpers/OAuthFlowHandler.mjs')
const { Validation } = await import('../../../src/task/Validation.mjs')

describe('McpAuthMiddleware HTTP Handlers', () => {
    let app
    let middleware
    let mockAuthHandler
    let mockTokenValidator
    let mockOAuthFlowHandler

    beforeEach(async () => {
        jest.clearAllMocks()

        // Setup mock auth handler
        mockAuthHandler = {
            provider: {
                normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }),
                generateEndpoints: jest.fn().mockReturnValue({
                    endpoints: {
                        jwksUrl: 'https://tenant.auth0.com/.well-known/jwks.json'
                    }
                })
            },
            tokenValidator: {
                validateToken: jest.fn().mockResolvedValue({
                    isValid: true,
                    decoded: { sub: 'user123', aud: 'https://api.example.com' }
                })
            },
            flowHandler: {
                initiateAuthFlow: jest.fn().mockReturnValue({
                    authorizationUrl: 'https://tenant.auth0.com/authorize?client_id=test',
                    state: 'test-state'
                }),
                handleCallback: jest.fn().mockResolvedValue({
                    success: true,
                    tokens: { access_token: 'test-token' }
                })
            }
        }

        // Setup mock TokenValidator
        mockTokenValidator = {
            validateForRoute: jest.fn().mockResolvedValue({
                isValid: true,
                decoded: { sub: 'user123', scope: 'openid profile' }
            }),
            validateWithAudienceBinding: jest.fn().mockResolvedValue({
                isValid: true,
                decoded: { sub: 'user123', scope: 'openid profile' },
                audienceBinding: { isValidAudience: true }
            })
        }

        // Setup mock OAuthFlowHandler
        mockOAuthFlowHandler = {
            initiateAuthorizationCodeFlowForRoute: jest.fn().mockReturnValue({
                authorizationUrl: 'https://tenant.auth0.com/authorize?client_id=test',
                state: 'test-state',
                routePath: '/api'
            }),
            handleAuthorizationCallbackForRoute: jest.fn().mockResolvedValue({
                success: true,
                tokens: { access_token: 'test-token' },
                routePath: '/api'
            })
        }

        // Setup mocks
        AuthTypeFactory.createAuthHandler.mockResolvedValue(mockAuthHandler)
        TokenValidator.createForMultiRealm.mockReturnValue(mockTokenValidator)
        OAuthFlowHandler.createForMultiRealm.mockReturnValue(mockOAuthFlowHandler)
        Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

        // Create middleware
        const routes = {
            '/api': {
                authType: 'oauth21_auth0',
                providerUrl: 'https://tenant.auth0.com',
                clientId: 'test-client-id',
                clientSecret: 'test-client-secret',
                scope: 'openid profile email',
                audience: 'https://api.example.com',
                realm: 'api-realm',
                requiredScopes: ['openid', 'profile'],
                forceHttps: false  // Disable HTTPS requirement for tests
            }
        }

        middleware = await McpAuthMiddleware.create({ routes, silent: true })

        // Create Express app for testing
        app = express()
        app.use(express.json()) // Parse JSON bodies for POST requests
        app.use(express.urlencoded({ extended: true })) // Parse form bodies for POST requests
        app.use(middleware.router())
    })

    describe('OAuth login endpoint', () => {
        test('GET /api/auth/login initiates OAuth flow', async () => {
            const response = await request(app)
                .get('/api/auth/login')
                .expect(302)

            expect(response.headers.location).toContain('https://tenant.auth0.com/authorize')
            expect(mockOAuthFlowHandler.initiateAuthorizationCodeFlowForRoute).toHaveBeenCalledWith(
                expect.objectContaining({
                    routePath: '/api'
                })
            )
        })

        test('GET /api/auth/login with query parameters', async () => {
            const response = await request(app)
                .get('/api/auth/login?scopes=read:users&audience=custom-api')
                .expect(302)

            expect(mockOAuthFlowHandler.initiateAuthorizationCodeFlowForRoute).toHaveBeenCalledWith(
                expect.objectContaining({
                    routePath: '/api',
                    resourceIndicators: expect.any(Array),
                    scopes: expect.any(Array)
                })
            )
        })

        test('handles HTTPS enforcement when forceHttps=true', async () => {
            // Create middleware with forceHttps=true
            const httpsRoutes = {
                '/secure': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'secure-client',
                    clientSecret: 'secure-secret',
                    scope: 'openid profile',
                    audience: 'https://secure.example.com',
                    requiredScopes: ['openid', 'profile'],
                    forceHttps: true
                }
            }

            const httpsMiddleware = await McpAuthMiddleware.create({ routes: httpsRoutes, silent: true })
            const httpsApp = express()
            httpsApp.use(httpsMiddleware.router())

            const response = await request(httpsApp)
                .get('/secure/auth/login')
                .expect(400)

            expect(response.body).toEqual({
                error: 'invalid_request',
                error_description: 'OAuth 2.1 requires HTTPS for all endpoints. Please use https:// instead of http://',
                oauth_compliance: 'OAuth 2.1 Section 3.1',
                documentation: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics'
            })
        })
    })

    describe('OAuth callback endpoint', () => {
        test('GET /api/auth/callback handles successful callback', async () => {
            const response = await request(app)
                .get('/api/auth/callback?code=test-code&state=test-state')
                .expect(200)

            expect(response.body).toEqual({
                message: 'Authentication successful',
                access_token: 'test-token',
                realm: 'api-realm',
                route: '/api',
                usage: 'Use Bearer token for /api endpoints'
            })
            
            expect(mockOAuthFlowHandler.handleAuthorizationCallbackForRoute).toHaveBeenCalledWith(
                expect.objectContaining({
                    code: 'test-code',
                    state: 'test-state'
                })
            )
        })

        test('POST /api/auth/callback handles successful callback', async () => {
            const response = await request(app)
                .post('/api/auth/callback?code=test-code&state=test-state')
                .expect(200)

            expect(response.body).toEqual({
                message: 'Authentication successful',
                access_token: 'test-token',
                realm: 'api-realm',
                route: '/api',
                usage: 'Use Bearer token for /api endpoints'
            })
        })

        test('handles callback error', async () => {
            mockOAuthFlowHandler.handleAuthorizationCallbackForRoute.mockResolvedValue({
                success: false,
                error: 'invalid_grant',
                error_description: 'Authorization code is invalid'
            })

            const response = await request(app)
                .get('/api/auth/callback?code=invalid-code&state=test-state')
                .expect(400)

            expect(response.body).toEqual({
                error: 'authentication_failed',
                error_description: 'invalid_grant'
            })
        })

        test('handles callback exception', async () => {
            mockOAuthFlowHandler.handleAuthorizationCallbackForRoute.mockRejectedValue(
                new Error('Network connection failed')
            )

            const response = await request(app)
                .get('/api/auth/callback?code=test-code&state=test-state')
                .expect(500)

            expect(response.body).toEqual({
                error: 'server_error',
                error_description: 'Internal authentication error'
            })
        })

        test('handles missing code parameter', async () => {
            const response = await request(app)
                .get('/api/auth/callback?state=test-state')
                .expect(400)

            expect(response.body.error).toBe('invalid_request')
            expect(response.body.error_description).toContain('Missing code or state parameter')
        })

        test('handles missing state parameter', async () => {
            const response = await request(app)
                .get('/api/auth/callback?code=test-code')
                .expect(400)

            expect(response.body.error).toBe('invalid_request')
            expect(response.body.error_description).toContain('Missing code or state parameter')
        })
    })

    describe('Protected resource metadata endpoint', () => {
        test('GET /.well-known/oauth-protected-resource/api returns metadata', async () => {
            const response = await request(app)
                .get('/.well-known/oauth-protected-resource/api')
                .expect(200)

            expect(response.body).toHaveProperty('resource')
            expect(response.body).toHaveProperty('authorization_servers')
            expect(response.body).toHaveProperty('scopes_supported')
            expect(response.body).toHaveProperty('route_info')
            expect(response.body).toHaveProperty('links')
            
            expect(response.body.resource).toContain('/api')
            expect(response.body.route_info.path).toBe('/api')
            expect(response.body.route_info.realm).toBe('api-realm')
        })
    })

    describe('Route discovery endpoint', () => {
        test('GET /api/discovery returns route information', async () => {
            const response = await request(app)
                .get('/api/discovery')
                .expect(200)

            expect(response.body).toHaveProperty('route', '/api')
            expect(response.body).toHaveProperty('endpoints')
            expect(response.body).toHaveProperty('authFlow', 'authorization-code')
            expect(response.body).toHaveProperty('realm', 'api-realm')
            expect(response.body).toHaveProperty('scopes')
            expect(response.body).toHaveProperty('security')
            
            expect(response.body.endpoints).toHaveProperty('login')
            expect(response.body.endpoints).toHaveProperty('callback')
            expect(response.body.endpoints.login).toContain('/api/auth/login')
            expect(response.body.endpoints.callback).toContain('/api/auth/callback')
            
            expect(response.body.scopes.required).toEqual(['openid', 'profile'])
        })
    })

    describe('Global well-known endpoints', () => {
        test('GET /.well-known/oauth-authorization-server handles server error', async () => {
            const response = await request(app)
                .get('/.well-known/oauth-authorization-server')
                .expect(500)
            
            expect(response.body).toEqual({
                error: 'Internal server error'
            })
        })

        test('GET /.well-known/jwks.json returns JWKS', async () => {
            // Mock JWKS response
            const mockJwks = {
                keys: [
                    {
                        kty: 'RSA',
                        kid: 'test-key-id',
                        use: 'sig',
                        alg: 'RS256',
                        n: 'test-n-value',
                        e: 'AQAB'
                    }
                ]
            }

            // Mock fetch for JWKS
            const mockFetch = jest.fn().mockResolvedValue({
                ok: true,
                json: jest.fn().mockResolvedValue(mockJwks)
            })
            global.fetch = mockFetch

            const response = await request(app)
                .get('/.well-known/jwks.json')
                .expect(200)

            expect(response.body).toHaveProperty('keys')
            expect(Array.isArray(response.body.keys)).toBe(true)
        })
    })

    describe('Protected request handling', () => {
        test('blocks request without Authorization header', async () => {
            // Create a test app with protected endpoint
            const testApp = express()
            testApp.use(express.json())
            testApp.use(express.urlencoded({ extended: true }))
            testApp.use(middleware.router())
            testApp.get('/api/protected', (req, res) => {
                res.json({ message: 'Protected content' })
            })

            const response = await request(testApp)
                .get('/api/protected')
                .expect(401)

            expect(response.body).toEqual({
                error: 'Unauthorized',
                message: 'Authorization header required',
                error_description: 'missing_authorization_header',
                login_url: expect.any(String),
                protected_resource_metadata: expect.any(String),
                route: '/api'
            })
        })

        test('blocks request with invalid token', async () => {
            // Create fresh middleware with mock that returns invalid token
            const invalidTokenValidator = {
                validateForRoute: jest.fn().mockResolvedValue({
                    isValid: false,
                    error: 'Token expired'
                }),
                validateWithAudienceBinding: jest.fn().mockResolvedValue({
                    isValid: false,
                    error: 'Token expired'
                })
            }
            
            TokenValidator.createForMultiRealm.mockReturnValueOnce(invalidTokenValidator)
            
            const testRoutes = {
                '/api': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client-id',
                    clientSecret: 'test-client-secret',
                    scope: 'openid profile email',
                    audience: 'https://api.example.com',
                    realm: 'api-realm',
                    requiredScopes: ['openid', 'profile'],
                    forceHttps: false
                }
            }
            
            const testMiddleware = await McpAuthMiddleware.create({ routes: testRoutes, silent: true })

            // Create a test app with protected endpoint
            const testApp = express()
            testApp.use(express.json())
            testApp.use(express.urlencoded({ extended: true }))
            testApp.use(testMiddleware.router())
            testApp.get('/api/protected', (req, res) => {
                res.json({ message: 'Protected content' })
            })

            const response = await request(testApp)
                .get('/api/protected')
                .set('Authorization', 'Bearer invalid-token')
                .expect(401)

            expect(response.body).toEqual({
                error: 'Unauthorized',
                message: 'Token expired',
                error_description: 'Token expired',
                login_url: expect.any(String),
                protected_resource_metadata: expect.any(String),
                route: '/api'
            })
        }, 10000)

        test('allows request with valid token', async () => {
            // Create a test endpoint to verify middleware passes through
            const testApp = express()
            testApp.use(middleware.router())
            testApp.get('/api/test-resource', (req, res) => {
                res.json({ message: 'Access granted', user: req.user })
            })

            const response = await request(testApp)
                .get('/api/test-resource')
                .set('Authorization', 'Bearer valid-token')
                .expect(200)

            expect(response.body.message).toBe('Access granted')
            expect(response.body.user).toBeDefined()
            expect(response.body.user.sub).toBe('user123')
        }, 10000)

        test('handles token validation edge cases', async () => {
            // This test covers edge case scenarios in token validation
            // ensuring the middleware behaves correctly under various conditions
            
            // Create a test app with protected endpoint
            const testApp = express()
            testApp.use(express.json())
            testApp.use(express.urlencoded({ extended: true }))
            testApp.use(middleware.router())
            testApp.get('/api/protected', (req, res) => {
                res.json({ message: 'Protected content' })
            })
            
            // Test successful request - should work with valid token mock
            const response = await request(testApp)
                .get('/api/protected')
                .set('Authorization', 'Bearer valid-token')
                .expect(200)

            // Should reach the protected endpoint
            expect(response.body).toEqual({
                message: 'Protected content'
            })
        }, 10000)
    })

    describe('forceHttps=false scenarios', () => {
        test('allows HTTP when forceHttps=false', async () => {
            const nonHttpsRoutes = {
                '/dev': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'dev-client',
                    clientSecret: 'dev-secret',
                    scope: 'openid profile',
                    audience: 'https://dev.example.com',
                    requiredScopes: ['openid', 'profile'],
                    forceHttps: false
                }
            }

            const devMiddleware = await McpAuthMiddleware.create({ routes: nonHttpsRoutes, silent: true })
            const devApp = express()
            devApp.use(devMiddleware.router())

            const response = await request(devApp)
                .get('/dev/auth/login')
                .expect(302) // Should redirect (not block with 400)

            expect(response.headers.location).toContain('https://tenant.auth0.com/authorize')
        })
    })

    describe('route configuration edge cases', () => {
        test('handles route with custom endpoints', async () => {
            const customRoutes = {
                '/custom': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://custom.auth0.com',
                    clientId: 'custom-client',
                    clientSecret: 'custom-secret',
                    scope: 'openid profile custom:access',
                    audience: 'https://custom.example.com',
                    tokenEndpoint: 'https://custom.auth0.com/oauth/token',
                    userInfoEndpoint: 'https://custom.auth0.com/userinfo',
                    requiredScopes: ['openid', 'profile'],
                    forceHttps: false
                }
            }

            const customMiddleware = await McpAuthMiddleware.create({ routes: customRoutes, silent: true })
            const customApp = express()
            customApp.use(customMiddleware.router())

            const response = await request(customApp)
                .get('/custom/discovery')
                .expect(200)

            expect(response.body.route).toBe('/custom')
            expect(response.body.authFlow).toBe('authorization-code')
        })
    })
})