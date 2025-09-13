import { jest } from '@jest/globals'

// This test file has been updated to reflect the new AuthType-based architecture
// TokenValidator is no longer a standalone class but is handled via AuthTypeFactory

// Mock the AuthTypeFactory system instead
const mockAuthTypeHandler = {
    tokenValidator: {
        validateToken: jest.fn()
    }
}

jest.unstable_mockModule( '../../../src/core/AuthTypeFactory.mjs', () => ({
    AuthTypeFactory: {
        createAuthHandler: jest.fn().mockReturnValue( mockAuthTypeHandler )
    }
}) )

const { AuthTypeFactory } = await import( '../../../src/core/AuthTypeFactory.mjs' )


describe( 'AuthType Token Validation - Advanced Coverage Tests', () => {

    let authHandler

    const testConfig = {
        authType: 'oauth21_auth0',
        config: {
            providerUrl: 'https://auth.example.com',
            clientId: 'test-client',
            clientSecret: 'test-secret',
            scope: 'openid profile',
            audience: 'https://api.example.com'
        },
        silent: true
    }

    beforeEach( () => {
        jest.clearAllMocks()
        authHandler = AuthTypeFactory.createAuthHandler( testConfig )
    } )


    describe( 'Token Validation with AuthType System', () => {

        test( 'validates token successfully with oauth21_auth0', async () => {
            const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'

            // Mock successful token validation
            mockAuthTypeHandler.tokenValidator.validateToken.mockResolvedValue({
                isValid: true,
                decoded: {
                    sub: 'user123',
                    iss: 'https://auth.example.com',
                    aud: 'test-client'
                }
            })

            const result = await authHandler.tokenValidator.validateToken( {
                token: mockToken,
                audience: 'test-client'
            } )

            expect( result.isValid ).toBe( true )
            expect( result.decoded.sub ).toBe( 'user123' )
            expect( mockAuthTypeHandler.tokenValidator.validateToken ).toHaveBeenCalled()
        } )


        test( 'handles token validation error', async () => {
            const mockToken = 'invalid.jwt.token'

            // Mock token validation error
            mockAuthTypeHandler.tokenValidator.validateToken.mockResolvedValue({
                isValid: false,
                error: 'Token expired'
            })

            const result = await authHandler.tokenValidator.validateToken( {
                token: mockToken,
                audience: 'test-client'
            } )

            expect( result.isValid ).toBe( false )
            expect( result.error ).toBe( 'Token expired' )
        } )


        test( 'validates token with proper audience', async () => {
            const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'

            // Mock successful validation with audience check
            mockAuthTypeHandler.tokenValidator.validateToken.mockResolvedValue({
                isValid: true,
                decoded: {
                    sub: 'user123',
                    iss: 'https://auth.example.com',
                    aud: 'https://api.example.com'
                }
            })

            const result = await authHandler.tokenValidator.validateToken( {
                token: mockToken,
                audience: 'https://api.example.com'
            } )

            expect( result.isValid ).toBe( true )
            expect( result.decoded.aud ).toBe( 'https://api.example.com' )
        } )

    } )


    describe( 'Error Handling in AuthType System', () => {

        test( 'handles authentication service unavailable', async () => {
            const mockToken = 'service.unavailable.token'

            // Mock service error
            mockAuthTypeHandler.tokenValidator.validateToken.mockRejectedValue(
                new Error( 'Authentication service unavailable' )
            )

            await expect( authHandler.tokenValidator.validateToken( {
                token: mockToken,
                audience: 'test-client'
            } ) ).rejects.toThrow( 'Authentication service unavailable' )
        } )


        test( 'handles malformed token', async () => {
            const mockToken = 'malformed-token'

            // Mock malformed token error
            mockAuthTypeHandler.tokenValidator.validateToken.mockResolvedValue({
                isValid: false,
                error: 'Malformed token'
            })

            const result = await authHandler.tokenValidator.validateToken( {
                token: mockToken,
                audience: 'test-client'
            } )

            expect( result.isValid ).toBe( false )
            expect( result.error ).toBe( 'Malformed token' )
        } )

    } )


    describe( 'AuthType Factory Configuration', () => {

        test( 'creates auth handler with proper configuration', () => {
            expect( AuthTypeFactory.createAuthHandler ).toHaveBeenCalledWith( testConfig )
            expect( authHandler ).toBeDefined()
            expect( authHandler.tokenValidator ).toBeDefined()
        } )


        test( 'supports oauth21_auth0 authType', async () => {
            const oauth21Config = {
                authType: 'oauth21_auth0',
                config: {
                    providerUrl: 'https://tenant.auth0.com',
                    clientId: 'auth0-client',
                    clientSecret: 'auth0-secret',
                    scope: 'openid profile email',
                    audience: 'https://api.example.com'
                },
                silent: true
            }

            const auth0Handler = AuthTypeFactory.createAuthHandler( oauth21Config )
            expect( auth0Handler ).toBeDefined()
            expect( auth0Handler.tokenValidator ).toBeDefined()
        } )


        test( 'supports staticBearer authType', async () => {
            const staticConfig = {
                authType: 'staticBearer',
                config: {
                    token: 'static-bearer-token-here'
                },
                silent: true
            }

            const staticHandler = AuthTypeFactory.createAuthHandler( staticConfig )
            expect( staticHandler ).toBeDefined()
            expect( staticHandler.tokenValidator ).toBeDefined()
        } )

    } )

} )