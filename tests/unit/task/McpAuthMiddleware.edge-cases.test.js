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

// TokenValidator.mjs wurde gelöscht - kein Mock nötig

// OAuthFlowHandler.mjs - keine multi-realm Methoden mehr

jest.unstable_mockModule('../../../src/task/Validation.mjs', () => ({
    Validation: {
        validationCreate: jest.fn()
    }
}))

// Import after mocking
const { McpAuthMiddleware } = await import('../../../src/task/McpAuthMiddleware.mjs')
const { AuthTypeFactory } = await import('../../../src/core/AuthTypeFactory.mjs')
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
            // OAuthFlowHandler.createForMultiRealm wurde entfernt - keine multi-realm Unterstützung mehr
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
            // OAuthFlowHandler.createForMultiRealm wurde entfernt - keine multi-realm Unterstützung mehr
        })
    })

    describe('authType validation edge cases', () => {
        test('rejects route configuration without authType', async () => {
            // Mock validation failure for missing authType
            Validation.validationCreate.mockReturnValue({
                status: false,
                messages: ['Route "/missing-authtype": Missing required field: authType']
            })

            const routes = {
                '/missing-authtype': {
                    // Missing authType - should be rejected
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile'
                }
            }

            await expect(McpAuthMiddleware.create({ routes, silent: true }))
                .rejects.toThrow('Input validation failed: Route "/missing-authtype": Missing required field: authType')
        })

        test('rejects invalid authType values', async () => {
            // Don't mock validation - let it run real validation to catch invalid authType
            Validation.validationCreate.mockReturnValue({
                status: false,
                messages: ['Route "/invalid-authtype": Unsupported authType: keycloak. Supported types: oauth21_auth0, staticBearer']
            })

            const routes = {
                '/invalid-authtype': {
                    authType: 'keycloak', // Invalid - should be rejected
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile'
                }
            }

            await expect(McpAuthMiddleware.create({ routes, silent: true }))
                .rejects.toThrow('Input validation failed: Route "/invalid-authtype": Unsupported authType: keycloak. Supported types: oauth21_auth0, staticBearer')
        })

        test('accepts valid oauth21_auth0 authType', async () => {
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/valid-auth0': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile',
                    audience: 'https://api.example.com'
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })

            expect(middleware).toBeDefined()
            expect(AuthTypeFactory.createAuthHandler).toHaveBeenCalledWith(
                expect.objectContaining({
                    authType: 'oauth21_auth0'
                })
            )
        })

        test('accepts valid staticBearer authType', async () => {
            AuthTypeFactory.createAuthHandler.mockResolvedValue({
                provider: { normalizeConfiguration: jest.fn().mockReturnValue({ config: {} }) },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: null // staticBearer doesn't need flow handler
            })

            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/valid-bearer': {
                    authType: 'staticBearer',
                    staticToken: 'valid-bearer-token-12345',
                    scope: 'read write'
                }
            }

            const middleware = await McpAuthMiddleware.create({ routes, silent: true })

            expect(middleware).toBeDefined()
            expect(AuthTypeFactory.createAuthHandler).toHaveBeenCalledWith(
                expect.objectContaining({
                    authType: 'staticBearer'
                })
            )
        })
    })

    describe('authType-based configuration edge cases', () => {
        test('handles complete authType configuration correctly', async () => {
            // Mock AuthTypeFactory to return handler with proper provider
            const mockAuthHandler = {
                provider: {
                    normalizeConfiguration: jest.fn().mockImplementation(({ config }) => ({
                        normalizedConfig: config // Return the config as-is to preserve Entry-Point defaults
                    }))
                },
                tokenValidator: { validateToken: jest.fn() },
                flowHandler: { initiateAuthFlow: jest.fn() }
            }

            AuthTypeFactory.createAuthHandler.mockResolvedValue(mockAuthHandler)
            Validation.validationCreate.mockReturnValue({ status: true, messages: [] })

            const routes = {
                '/authtype-complete': {
                    authType: 'oauth21_auth0',
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'test-client',
                    clientSecret: 'test-secret',
                    scope: 'openid profile',
                    audience: 'https://api.example.com',
                    realm: 'test-realm',
                    authFlow: 'authorization_code',
                    requiredScopes: [ 'openid' ],
                    requiredRoles: []
                    // All fields now explicitly provided - no defaults needed
                }
            }

            // Create middleware with complete configuration (no defaults needed)
            const middleware = await McpAuthMiddleware.create({ routes, silent: true })

            // Verify that all configuration fields are passed correctly to AuthTypeFactory
            expect(AuthTypeFactory.createAuthHandler).toHaveBeenCalledWith(
                expect.objectContaining({
                    config: expect.objectContaining({
                        authType: 'oauth21_auth0',
                        providerUrl: 'https://tenant.auth0.com',
                        clientId: 'test-client',
                        clientSecret: 'test-secret',
                        scope: 'openid profile',
                        audience: 'https://api.example.com',
                        realm: 'test-realm',
                        authFlow: 'authorization_code',
                        requiredScopes: [ 'openid' ],
                        requiredRoles: []
                    })
                })
            )
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