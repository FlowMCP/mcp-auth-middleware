import { jest } from '@jest/globals'

// Mock all external dependencies
jest.unstable_mockModule('express', () => ({
    default: {
        Router: jest.fn(() => ({
            get: jest.fn(),
            post: jest.fn(),
            use: jest.fn()
        }))
    }
}))

jest.unstable_mockModule('../../../src/core/AuthTypeFactory.mjs', () => ({
    AuthTypeFactory: {
        createAuthHandler: jest.fn()
    }
}))

jest.unstable_mockModule('../../../src/helpers/TokenValidator.mjs', () => ({
    TokenValidator: {
        createForMultiRealm: jest.fn().mockReturnValue({
            validateForRoute: jest.fn()
        })
    }
}))

jest.unstable_mockModule('../../../src/helpers/OAuthFlowHandler.mjs', () => ({
    OAuthFlowHandler: {
        createForMultiRealm: jest.fn().mockReturnValue({
            initiateAuthorizationCodeFlowForRoute: jest.fn()
        })
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

describe('McpAuthMiddleware Edge Cases', () => {
    let mockRouter

    beforeEach(() => {
        jest.clearAllMocks()
        
        // Setup default router mock
        mockRouter = {
            get: jest.fn(),
            post: jest.fn(),
            use: jest.fn()
        }
        
        // Setup default validation success
        Validation.validationCreate.mockReturnValue({
            status: true,
            messages: []
        })
    })

    describe('constructor edge cases', () => {
        test('creates middleware with all default values', () => {
            const middleware = new McpAuthMiddleware({})
            
            expect(middleware).toBeInstanceOf(McpAuthMiddleware)
        })

        test('creates middleware with explicit silent false', () => {
            const middleware = new McpAuthMiddleware({ silent: false })
            
            expect(middleware).toBeInstanceOf(McpAuthMiddleware)
        })
    })

    describe('create method edge cases', () => {
        test('throws error when routes is null', async () => {
            // Mock validation failure for null routes
            Validation.validationCreate.mockReturnValue({
                status: false,
                messages: ['routes: Missing value']
            })

            await expect(McpAuthMiddleware.create({ routes: null }))
                .rejects.toThrow('Input validation failed: routes: Missing value')
        })

        test('throws error when routes is undefined', async () => {
            // Mock validation failure for undefined routes
            Validation.validationCreate.mockReturnValue({
                status: false,
                messages: ['routes: Missing value']
            })

            await expect(McpAuthMiddleware.create({}))
                .rejects.toThrow('Input validation failed: routes: Missing value')
        })

        test('throws error when routes is string instead of object', async () => {
            // Mock validation failure for string routes
            Validation.validationCreate.mockReturnValue({
                status: false,
                messages: ['routes: Must be an object']
            })

            await expect(McpAuthMiddleware.create({ routes: 'invalid' }))
                .rejects.toThrow('Input validation failed: routes: Must be an object')
        })

        test('throws error when routes is array instead of object', async () => {
            // Mock validation failure for array routes
            Validation.validationCreate.mockReturnValue({
                status: false,
                messages: ['routes: Must be an object']
            })

            await expect(McpAuthMiddleware.create({ routes: [] }))
                .rejects.toThrow('Input validation failed: routes: Must be an object')
        })

        test('throws error when routes object is empty', async () => {
            await expect(McpAuthMiddleware.create({ routes: {} }))
                .rejects.toThrow('No routes configured - at least one route is required')
        })
    })

    describe('route configuration validation edge cases', () => {
        test('throws error for route path not starting with /', async () => {
            const routes = {
                'api': { // Missing leading slash
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile',
                    audience: 'https://api.example.com'
                }
            }

            await expect(McpAuthMiddleware.create({ routes, silent: true }))
                .rejects.toThrow('Must start with "/" - Invalid route path: api')
        })

        test('throws error for empty route path', async () => {
            const routes = {
                '': { // Empty route path
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile',
                    audience: 'https://api.example.com'
                }
            }

            await expect(McpAuthMiddleware.create({ routes, silent: true }))
                .rejects.toThrow('Must start with "/" - Invalid route path: ')
        })

        test('throws error when validation fails', async () => {
            Validation.validationCreate.mockReturnValue({
                status: false,
                messages: ['Missing required field: clientId', 'Invalid providerUrl format']
            })

            const routes = {
                '/api': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'invalid-url'
                    // Missing other required fields
                }
            }

            await expect(McpAuthMiddleware.create({ routes, silent: true }))
                .rejects.toThrow('Input validation failed: Missing required field: clientId, Invalid providerUrl format')
        })
    })

    describe('AuthType handler creation edge cases', () => {
        test('throws error when AuthType handler creation fails', async () => {
            // Mock validation success
            Validation.validationCreate.mockReturnValue({
                status: true,
                messages: []
            })

            // Mock AuthTypeFactory failure
            AuthTypeFactory.createAuthHandler.mockRejectedValue(
                new Error('Invalid authType: unknown_type')
            )

            const routes = {
                '/api': {
                    authType: 'unknown_type', // Invalid auth type
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile',
                    audience: 'https://api.example.com'
                }
            }

            await expect(McpAuthMiddleware.create({ routes, silent: true }))
                .rejects.toThrow('Failed to create AuthType handler for route /api: Invalid authType: unknown_type')
        })

        test('handles AuthType handler creation with different error message', async () => {
            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })
            
            AuthTypeFactory.createAuthHandler.mockRejectedValue(
                new Error('Configuration validation failed')
            )

            const routes = {
                '/admin': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com'
                    // Missing required fields to trigger error
                }
            }

            await expect(McpAuthMiddleware.create({ routes, silent: true }))
                .rejects.toThrow('Failed to create AuthType handler for route /admin: Configuration validation failed')
        })
    })

    describe('resource URI parsing edge cases', () => {
        test('parses resourceUri for baseRedirectUri extraction', async () => {
            // Mock successful AuthType handler creation
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/api': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile',
                    audience: 'https://api.example.com',
                    resourceUri: 'https://custom-domain.example.com/api'
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })
            
            expect(middleware).toBeDefined()
            expect(OAuthFlowHandler.createForMultiRealm).toHaveBeenCalledWith(
                expect.objectContaining({
                    baseRedirectUri: 'https://custom-domain.example.com'
                })
            )
        })

        test('uses default baseRedirectUri when no resourceUri provided', async () => {
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/api': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile',
                    audience: 'https://api.example.com'
                    // No resourceUri provided
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })
            
            expect(middleware).toBeDefined()
            expect(OAuthFlowHandler.createForMultiRealm).toHaveBeenCalledWith(
                expect.objectContaining({
                    baseRedirectUri: 'http://localhost:3000'
                })
            )
        })
    })

    describe('legacy provider detection edge cases', () => {
        test('handles legacy Auth0 provider configuration (without authType)', async () => {
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/legacy-auth0': {
                    // No authType - should trigger legacy detection
                    providerUrl: 'https://my-tenant.auth0.com',
                    clientId: 'legacy-client',
                    clientSecret: 'legacy-secret',
                    scope: 'openid profile email',
                    audience: 'https://api.example.com'
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })
            
            expect(middleware).toBeDefined()
            
            const routeConfig = middleware.getRouteConfig({ routePath: '/legacy-auth0' })
            expect(routeConfig.authorizationUrl).toBe('https://my-tenant.auth0.com/authorize')
            expect(routeConfig.tokenUrl).toBe('https://my-tenant.auth0.com/oauth/token')
            expect(routeConfig.jwksUrl).toBe('https://my-tenant.auth0.com/.well-known/jwks.json')
            expect(routeConfig.userInfoUrl).toBe('https://my-tenant.auth0.com/userinfo')
            expect(routeConfig.introspectionUrl).toBe('https://my-tenant.auth0.com/oauth/token/introspection')
        })

        test('handles legacy Keycloak provider configuration (without authType)', async () => {
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/legacy-keycloak': {
                    // No authType - should trigger legacy detection
                    providerUrl: 'https://keycloak.example.com',
                    realm: 'master',
                    clientId: 'keycloak-client',
                    clientSecret: 'keycloak-secret',
                    scope: 'openid profile email'
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })
            
            expect(middleware).toBeDefined()
            
            const routeConfig = middleware.getRouteConfig({ routePath: '/legacy-keycloak' })
            expect(routeConfig.authorizationUrl).toBe('https://keycloak.example.com/realms/master/protocol/openid-connect/auth')
            expect(routeConfig.tokenUrl).toBe('https://keycloak.example.com/realms/master/protocol/openid-connect/token')
            expect(routeConfig.jwksUrl).toBe('https://keycloak.example.com/realms/master/protocol/openid-connect/certs')
            expect(routeConfig.userInfoUrl).toBe('https://keycloak.example.com/realms/master/protocol/openid-connect/userinfo')
            expect(routeConfig.introspectionUrl).toBe('https://keycloak.example.com/realms/master/protocol/openid-connect/token/introspect')
        })

        test('applies legacy configuration defaults correctly', async () => {
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/legacy-defaults': {
                    providerUrl: 'https://provider.example.com', // Not Auth0 - triggers Keycloak path
                    realm: 'test-realm',
                    clientId: 'test-client',
                    clientSecret: 'test-secret'
                    // Missing optional fields - should get defaults
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })
            
            const routeConfig = middleware.getRouteConfig({ routePath: '/legacy-defaults' })
            expect(routeConfig.authFlow).toBe('authorization-code')
            expect(routeConfig.requiredScopes).toEqual(['openid', 'profile'])
            expect(routeConfig.forceHttps).toBe(false) // Global forceHttps default is false
            expect(routeConfig.requiredRoles).toEqual([])
            expect(routeConfig.allowAnonymous).toBe(false)
        })

        test('allows overriding legacy configuration defaults', async () => {
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/legacy-custom': {
                    providerUrl: 'https://provider.example.com',
                    realm: 'custom-realm',
                    clientId: 'custom-client',
                    clientSecret: 'custom-secret',
                    
                    // Custom overrides
                    authFlow: 'client-credentials',
                    requiredScopes: ['custom:read', 'custom:write'],
                    forceHttps: false,
                    requiredRoles: ['admin', 'user'],
                    allowAnonymous: true,
                    
                    // Custom endpoint overrides
                    authorizationUrl: 'https://custom.example.com/auth',
                    tokenUrl: 'https://custom.example.com/token',
                    jwksUrl: 'https://custom.example.com/jwks',
                    userInfoUrl: 'https://custom.example.com/userinfo',
                    introspectionUrl: 'https://custom.example.com/introspect'
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })
            
            const routeConfig = middleware.getRouteConfig({ routePath: '/legacy-custom' })
            expect(routeConfig.authFlow).toBe('client-credentials')
            expect(routeConfig.requiredScopes).toEqual(['custom:read', 'custom:write'])
            expect(routeConfig.forceHttps).toBe(false)
            expect(routeConfig.requiredRoles).toEqual(['admin', 'user'])
            expect(routeConfig.allowAnonymous).toBe(true)
            
            // Should use custom endpoints instead of auto-generated ones
            expect(routeConfig.authorizationUrl).toBe('https://custom.example.com/auth')
            expect(routeConfig.tokenUrl).toBe('https://custom.example.com/token')
            expect(routeConfig.jwksUrl).toBe('https://custom.example.com/jwks')
            expect(routeConfig.userInfoUrl).toBe('https://custom.example.com/userinfo')
            expect(routeConfig.introspectionUrl).toBe('https://custom.example.com/introspect')
        })
    })

    describe('authType-based configuration edge cases', () => {
        test('applies authType configuration defaults correctly', async () => {
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/authtype-defaults': {
                    authType: 'oauth21_auth0', // Has authType - triggers new path
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile',
                    audience: 'https://api.example.com'
                    // Missing optional fields - should get defaults
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })
            
            const routeConfig = middleware.getRouteConfig({ routePath: '/authtype-defaults' })
            expect(routeConfig.authFlow).toBe('authorization-code') // Default
            expect(routeConfig.requiredRoles).toEqual([]) // Default
            expect(routeConfig.allowAnonymous).toBe(false) // Default
        })

        test('allows overriding authType configuration defaults', async () => {
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/authtype-custom': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile',
                    audience: 'https://api.example.com',
                    
                    // Custom overrides
                    authFlow: 'client-credentials',
                    requiredRoles: ['admin'],
                    allowAnonymous: true
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })
            
            const routeConfig = middleware.getRouteConfig({ routePath: '/authtype-custom' })
            expect(routeConfig.authFlow).toBe('client-credentials')
            expect(routeConfig.requiredRoles).toEqual(['admin'])
            expect(routeConfig.allowAnonymous).toBe(true)
        })
    })
})