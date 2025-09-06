import { jest } from '@jest/globals'

const mockKeycloakClient = jest.fn()
const mockTokenValidator = jest.fn()

jest.unstable_mockModule( '../../src/helpers/KeycloakClient.mjs', () => ({
    KeycloakClient: {
        create: mockKeycloakClient
    }
}) )

const mockOAuthFlowHandler = jest.fn()
const mockDynamicClientRegistration = jest.fn()

jest.unstable_mockModule( '../../src/helpers/TokenValidator.mjs', () => ({
    TokenValidator: {
        create: mockTokenValidator
    }
}) )

jest.unstable_mockModule( '../../src/helpers/OAuthFlowHandler.mjs', () => ({
    OAuthFlowHandler: {
        create: mockOAuthFlowHandler
    }
}) )

jest.unstable_mockModule( '../../src/helpers/DynamicClientRegistration.mjs', () => ({
    DynamicClientRegistration: {
        create: mockDynamicClientRegistration
    }
}) )

const { OAuthMiddleware } = await import( '../../src/OAuthMiddleware.mjs' )


describe( 'OAuthMiddleware', () => {
    let middleware
    let mockKeycloakClientInstance
    let mockTokenValidatorInstance
    let mockOAuthFlowHandlerInstance
    let mockDynamicClientRegistrationInstance

    beforeEach( () => {
        mockKeycloakClientInstance = {
            getJwks: jest.fn().mockReturnValue( { jwksData: { keys: [] } } ),
            validateToken: jest.fn().mockResolvedValue( { isValid: true } )
        }

        mockTokenValidatorInstance = {
            validate: jest.fn().mockReturnValue( { 
                isValid: true, 
                decoded: { sub: 'user123', scope: 'mcp:tools' }, 
                error: null 
            } )
        }

        mockOAuthFlowHandlerInstance = {
            initiateAuthorizationCodeFlow: jest.fn().mockReturnValue( {
                authorizationUrl: 'https://oauth.example.com/auth?code_challenge=abc',
                state: 'random-state'
            } ),
            handleAuthorizationCallback: jest.fn().mockResolvedValue( {
                success: true,
                tokens: { access_token: 'access-token' }
            } ),
            requestClientCredentials: jest.fn().mockResolvedValue( {
                tokens: { access_token: 'client-token' }
            } ),
            refreshAccessToken: jest.fn().mockResolvedValue( {
                success: true,
                tokens: { access_token: 'new-token' }
            } )
        }

        mockDynamicClientRegistrationInstance = {
            registerClient: jest.fn().mockResolvedValue( {
                success: true,
                clientId: 'new-client-id',
                clientSecret: 'new-client-secret'
            } )
        }

        mockKeycloakClient.mockReturnValue( mockKeycloakClientInstance )
        mockTokenValidator.mockReturnValue( mockTokenValidatorInstance )
        mockOAuthFlowHandler.mockReturnValue( mockOAuthFlowHandlerInstance )
        mockDynamicClientRegistration.mockReturnValue( mockDynamicClientRegistrationInstance )

        const { middleware: createdMiddleware } = OAuthMiddleware.create( {
            keycloakUrl: 'http://localhost:8080',
            realm: 'test-realm',
            clientId: 'test-client',
            clientSecret: 'test-secret',
            silent: true
        } )

        middleware = createdMiddleware
    } )

    describe( 'create', () => {
        test( 'creates middleware instance with valid configuration', () => {
            const { middleware } = OAuthMiddleware.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'test-client',
                clientSecret: 'test-secret'
            } )

            expect( middleware ).toBeDefined()
            expect( typeof middleware.mcp ).toBe( 'function' )
        } )
    } )

    describe( 'mcp middleware', () => {
        test( 'allows request with valid Bearer token', () => {
            const req = {
                headers: {
                    authorization: 'Bearer valid-token'
                }
            }
            const res = {}
            const next = jest.fn()

            const middlewareFunction = middleware.mcp()
            middlewareFunction( req, res, next )

            expect( next ).toHaveBeenCalled()
            expect( req.user ).toBeDefined()
            expect( req.user.sub ).toBe( 'user123' )
        } )

        test( 'rejects request without authorization header', () => {
            const req = { headers: {} }
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            }
            const next = jest.fn()

            const middlewareFunction = middleware.mcp()
            middlewareFunction( req, res, next )

            expect( res.status ).toHaveBeenCalledWith( 401 )
            expect( res.json ).toHaveBeenCalledWith( { 
                error: 'Authorization header required' 
            } )
            expect( next ).not.toHaveBeenCalled()
        } )

        test( 'rejects request with invalid authorization header format', () => {
            const req = {
                headers: {
                    authorization: 'Invalid format'
                }
            }
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            }
            const next = jest.fn()

            const middlewareFunction = middleware.mcp()
            middlewareFunction( req, res, next )

            expect( res.status ).toHaveBeenCalledWith( 401 )
            expect( res.json ).toHaveBeenCalledWith( { 
                error: 'Invalid authorization header format' 
            } )
            expect( next ).not.toHaveBeenCalled()
        } )

        test( 'rejects request with invalid token', () => {
            mockTokenValidatorInstance.validate.mockReturnValue( {
                isValid: false,
                error: 'Token expired',
                decoded: null
            } )

            const req = {
                headers: {
                    authorization: 'Bearer invalid-token'
                }
            }
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            }
            const next = jest.fn()

            const middlewareFunction = middleware.mcp()
            middlewareFunction( req, res, next )

            expect( res.status ).toHaveBeenCalledWith( 401 )
            expect( res.json ).toHaveBeenCalledWith( { 
                error: 'Token expired' 
            } )
            expect( next ).not.toHaveBeenCalled()
        } )
    } )

    describe( 'wellKnownAuthorizationServer', () => {
        test( 'returns correct authorization server metadata', () => {
            const req = {}
            const res = {
                json: jest.fn()
            }

            const wellKnownFunction = middleware.wellKnownAuthorizationServer()
            wellKnownFunction( req, res )

            expect( res.json ).toHaveBeenCalledWith(
                expect.objectContaining( {
                    issuer: 'http://localhost:8080/realms/test-realm',
                    authorization_endpoint: 'http://localhost:8080/realms/test-realm/protocol/openid-connect/auth',
                    token_endpoint: 'http://localhost:8080/realms/test-realm/protocol/openid-connect/token',
                    scopes_supported: expect.arrayContaining( [ 'openid', 'profile', 'email', 'mcp:tools', 'mcp:resources' ] ),
                    response_types_supported: [ 'code' ],
                    grant_types_supported: expect.arrayContaining( [ 'authorization_code', 'client_credentials', 'refresh_token' ] )
                } )
            )
        } )
    } )

    describe( 'wellKnownProtectedResource', () => {
        test( 'returns correct protected resource metadata', () => {
            const req = {}
            const res = {
                json: jest.fn()
            }

            const wellKnownFunction = middleware.wellKnownProtectedResource()
            wellKnownFunction( req, res )

            expect( res.json ).toHaveBeenCalledWith(
                expect.objectContaining( {
                    resource: 'http://localhost:8080/realms/test-realm',
                    authorization_servers: [ 'http://localhost:8080/realms/test-realm' ],
                    scopes_supported: expect.arrayContaining( [ 'mcp:tools', 'mcp:resources' ] )
                } )
            )
        } )
    } )

    describe( 'wellKnownJwks', () => {
        test( 'returns JWKS data from Keycloak client', () => {
            const mockJwksData = { keys: [ { kid: 'test-key' } ] }
            mockKeycloakClientInstance.getJwks.mockReturnValue( { jwksData: mockJwksData } )

            const req = {}
            const res = {
                json: jest.fn()
            }

            const wellKnownFunction = middleware.wellKnownJwks()
            wellKnownFunction( req, res )

            expect( res.json ).toHaveBeenCalledWith( mockJwksData )
        } )
    } )

    describe( 'OAuth flow methods', () => {
        test( 'initiateAuthorizationCodeFlow delegates to flow handler', () => {
            const result = middleware.initiateAuthorizationCodeFlow( {
                scopes: [ 'openid' ],
                resourceIndicators: [ 'https://api.example.com' ]
            } )

            expect( mockOAuthFlowHandlerInstance.initiateAuthorizationCodeFlow ).toHaveBeenCalledWith( {
                scopes: [ 'openid' ],
                resourceIndicators: [ 'https://api.example.com' ]
            } )
            expect( result ).toEqual( {
                authorizationUrl: 'https://oauth.example.com/auth?code_challenge=abc',
                state: 'random-state'
            } )
        } )

        test( 'handleAuthorizationCallback delegates to flow handler', async () => {
            const result = await middleware.handleAuthorizationCallback( {
                code: 'auth-code',
                state: 'test-state'
            } )

            expect( mockOAuthFlowHandlerInstance.handleAuthorizationCallback ).toHaveBeenCalledWith( {
                code: 'auth-code',
                state: 'test-state'
            } )
            expect( result ).toEqual( {
                success: true,
                tokens: { access_token: 'access-token' }
            } )
        } )

        test( 'requestClientCredentials delegates to flow handler', async () => {
            const result = await middleware.requestClientCredentials( {
                scopes: [ 'mcp:tools' ]
            } )

            expect( mockOAuthFlowHandlerInstance.requestClientCredentials ).toHaveBeenCalledWith( {
                scopes: [ 'mcp:tools' ]
            } )
            expect( result ).toEqual( {
                tokens: { access_token: 'client-token' }
            } )
        } )

        test( 'refreshAccessToken delegates to flow handler', async () => {
            const result = await middleware.refreshAccessToken( {
                refreshToken: 'refresh-token'
            } )

            expect( mockOAuthFlowHandlerInstance.refreshAccessToken ).toHaveBeenCalledWith( {
                refreshToken: 'refresh-token'
            } )
            expect( result ).toEqual( {
                success: true,
                tokens: { access_token: 'new-token' }
            } )
        } )
    } )

    describe( 'Dynamic client registration', () => {
        test( 'registerClient delegates to dynamic client registration', async () => {
            const result = await middleware.registerClient( {
                clientName: 'Test Client',
                redirectUris: [ 'https://app.example.com/callback' ],
                grantTypes: [ 'authorization_code' ]
            } )

            expect( mockDynamicClientRegistrationInstance.registerClient ).toHaveBeenCalledWith( {
                clientName: 'Test Client',
                redirectUris: [ 'https://app.example.com/callback' ],
                grantTypes: [ 'authorization_code' ]
            } )
            expect( result ).toEqual( {
                success: true,
                clientId: 'new-client-id',
                clientSecret: 'new-client-secret'
            } )
        } )
    } )

    describe( 'RBAC functionality', () => {
        test( 'setRBACRules stores rules correctly', () => {
            const rules = [
                {
                    path: '/api/admin',
                    methods: [ 'GET', 'POST' ],
                    requiredRoles: [ 'admin' ]
                },
                {
                    path: '/api/weather',
                    requiredScopes: [ 'mcp:tools:weather' ]
                }
            ]

            const result = middleware.setRBACRules( { rules } )

            expect( result ).toEqual( { success: true } )
        } )

        test( 'checkRBAC allows access when no rule exists', () => {
            const result = middleware.checkRBAC( {
                path: '/api/unrestricted',
                method: 'GET',
                roles: [],
                scopes: []
            } )

            expect( result ).toEqual( { allowed: true } )
        } )

        test( 'checkRBAC blocks access for wrong method', () => {
            middleware.setRBACRules( {
                rules: [ {
                    path: '/api/admin',
                    methods: [ 'GET' ],
                    requiredRoles: [ 'admin' ]
                } ]
            } )

            const result = middleware.checkRBAC( {
                path: '/api/admin',
                method: 'POST',
                roles: [ 'admin' ],
                scopes: []
            } )

            expect( result ).toEqual( { allowed: false, reason: 'Method not allowed' } )
        } )

        test( 'checkRBAC blocks access for missing required role', () => {
            middleware.setRBACRules( {
                rules: [ {
                    path: '/api/admin',
                    requiredRoles: [ 'admin', 'super-admin' ]
                } ]
            } )

            const result = middleware.checkRBAC( {
                path: '/api/admin',
                method: 'GET',
                roles: [ 'user' ],
                scopes: []
            } )

            expect( result ).toEqual( { allowed: false, reason: 'Missing required role' } )
        } )

        test( 'checkRBAC allows access with correct role', () => {
            middleware.setRBACRules( {
                rules: [ {
                    path: '/api/admin',
                    requiredRoles: [ 'admin', 'super-admin' ]
                } ]
            } )

            const result = middleware.checkRBAC( {
                path: '/api/admin',
                method: 'GET',
                roles: [ 'user', 'admin' ],
                scopes: []
            } )

            expect( result ).toEqual( { allowed: true } )
        } )

        test( 'checkRBAC blocks access for missing required scope', () => {
            middleware.setRBACRules( {
                rules: [ {
                    path: '/api/weather',
                    requiredScopes: [ 'mcp:tools:weather' ]
                } ]
            } )

            const result = middleware.checkRBAC( {
                path: '/api/weather',
                method: 'GET',
                roles: [],
                scopes: [ 'mcp:tools' ]
            } )

            expect( result ).toEqual( { allowed: false, reason: 'Missing required scope' } )
        } )

        test( 'checkRBAC allows access with correct scope', () => {
            middleware.setRBACRules( {
                rules: [ {
                    path: '/api/weather',
                    requiredScopes: [ 'mcp:tools:weather' ]
                } ]
            } )

            const result = middleware.checkRBAC( {
                path: '/api/weather',
                method: 'GET',
                roles: [],
                scopes: [ 'mcp:tools', 'mcp:tools:weather' ]
            } )

            expect( result ).toEqual( { allowed: true } )
        } )
    } )

    describe( 'mcpWithRBAC middleware', () => {
        beforeEach( () => {
            middleware.setRBACRules( {
                rules: [ {
                    path: '/api/admin',
                    requiredRoles: [ 'admin' ]
                } ]
            } )
        } )

        test( 'allows request with valid token and RBAC permissions', () => {
            mockTokenValidatorInstance.validate.mockReturnValue( {
                isValid: true,
                decoded: {
                    sub: 'user123',
                    scope: 'mcp:tools',
                    realm_access: { roles: [ 'admin' ] }
                },
                error: null
            } )

            const req = {
                headers: { authorization: 'Bearer valid-token' },
                path: '/api/admin',
                method: 'GET'
            }
            const res = {}
            const next = jest.fn()

            const rbacMiddleware = middleware.mcpWithRBAC()
            rbacMiddleware( req, res, next )

            expect( next ).toHaveBeenCalled()
            expect( req.user.sub ).toBe( 'user123' )
            expect( req.roles ).toEqual( [ 'admin' ] )
            expect( req.scopes ).toEqual( [ 'mcp:tools' ] )
        } )

        test( 'rejects request without authorization header', () => {
            const req = { headers: {}, path: '/api/admin', method: 'GET' }
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            }
            const next = jest.fn()

            const rbacMiddleware = middleware.mcpWithRBAC()
            rbacMiddleware( req, res, next )

            expect( res.status ).toHaveBeenCalledWith( 401 )
            expect( res.json ).toHaveBeenCalledWith( { error: 'Authorization header required' } )
            expect( next ).not.toHaveBeenCalled()
        } )

        test( 'rejects request with invalid token', () => {
            mockTokenValidatorInstance.validate.mockReturnValue( {
                isValid: false,
                error: 'Token expired',
                decoded: null
            } )

            const req = {
                headers: { authorization: 'Bearer invalid-token' },
                path: '/api/admin',
                method: 'GET'
            }
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            }
            const next = jest.fn()

            const rbacMiddleware = middleware.mcpWithRBAC()
            rbacMiddleware( req, res, next )

            expect( res.status ).toHaveBeenCalledWith( 401 )
            expect( res.json ).toHaveBeenCalledWith( { error: 'Token expired' } )
            expect( next ).not.toHaveBeenCalled()
        } )

        test( 'rejects request with insufficient RBAC permissions', () => {
            mockTokenValidatorInstance.validate.mockReturnValue( {
                isValid: true,
                decoded: {
                    sub: 'user123',
                    scope: 'mcp:tools',
                    realm_access: { roles: [ 'user' ] }
                },
                error: null
            } )

            const req = {
                headers: { authorization: 'Bearer valid-token' },
                path: '/api/admin',
                method: 'GET'
            }
            const res = {
                status: jest.fn().mockReturnThis(),
                json: jest.fn()
            }
            const next = jest.fn()

            const rbacMiddleware = middleware.mcpWithRBAC()
            rbacMiddleware( req, res, next )

            expect( res.status ).toHaveBeenCalledWith( 403 )
            expect( res.json ).toHaveBeenCalledWith( { error: 'Missing required role' } )
            expect( next ).not.toHaveBeenCalled()
        } )

        test( 'handles token without realm_access roles', () => {
            mockTokenValidatorInstance.validate.mockReturnValue( {
                isValid: true,
                decoded: {
                    sub: 'user123',
                    scope: 'mcp:tools'
                },
                error: null
            } )

            const req = {
                headers: { authorization: 'Bearer valid-token' },
                path: '/api/unrestricted',
                method: 'GET'
            }
            const res = {}
            const next = jest.fn()

            const rbacMiddleware = middleware.mcpWithRBAC()
            rbacMiddleware( req, res, next )

            expect( next ).toHaveBeenCalled()
            expect( req.roles ).toEqual( [] )
        } )

        test( 'handles token without scope', () => {
            mockTokenValidatorInstance.validate.mockReturnValue( {
                isValid: true,
                decoded: {
                    sub: 'user123',
                    realm_access: { roles: [ 'user' ] }
                },
                error: null
            } )

            const req = {
                headers: { authorization: 'Bearer valid-token' },
                path: '/api/unrestricted',
                method: 'GET'
            }
            const res = {}
            const next = jest.fn()

            const rbacMiddleware = middleware.mcpWithRBAC()
            rbacMiddleware( req, res, next )

            expect( next ).toHaveBeenCalled()
            expect( req.scopes ).toEqual( [] )
        } )
    } )
} )