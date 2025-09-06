import { jest } from '@jest/globals'

const mockFetch = jest.fn()
const mockCrypto = {
    randomBytes: jest.fn()
}

jest.unstable_mockModule( 'node-fetch', () => ({
    default: mockFetch
}) )

jest.unstable_mockModule( 'crypto', () => ({
    default: mockCrypto
}) )

const mockPKCEGenerator = {
    generatePKCEPair: jest.fn()
}

jest.unstable_mockModule( '../../../src/helpers/PKCEGenerator.mjs', () => ({
    PKCEGenerator: mockPKCEGenerator
}) )

const { OAuthFlowHandler } = await import( '../../../src/helpers/OAuthFlowHandler.mjs' )


describe( 'OAuthFlowHandler', () => {
    let flowHandler
    
    beforeEach( () => {
        flowHandler = OAuthFlowHandler.create( {
            keycloakUrl: 'http://localhost:8080',
            realm: 'test-realm',
            clientId: 'test-client',
            clientSecret: 'test-secret',
            redirectUri: 'http://localhost:3000/callback',
            silent: true
        } )
        
        mockFetch.mockClear()
        mockCrypto.randomBytes.mockClear()
        mockPKCEGenerator.generatePKCEPair.mockClear()
    } )

    afterEach( () => {
        jest.resetAllMocks()
    } )

    describe( 'create', () => {
        test( 'creates OAuthFlowHandler instance with valid configuration', () => {
            const handler = OAuthFlowHandler.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'test-client',
                clientSecret: 'test-secret',
                redirectUri: 'http://localhost:3000/callback'
            } )

            expect( handler ).toBeDefined()
            expect( typeof handler.initiateAuthorizationCodeFlow ).toBe( 'function' )
            expect( typeof handler.handleAuthorizationCallback ).toBe( 'function' )
            expect( typeof handler.requestClientCredentials ).toBe( 'function' )
            expect( typeof handler.refreshAccessToken ).toBe( 'function' )
        } )
    } )

    describe( 'initiateAuthorizationCodeFlow', () => {
        test( 'generates authorization URL with default parameters', () => {
            const mockStateBuffer = Buffer.from( 'test-state-123' )
            mockCrypto.randomBytes.mockReturnValue( mockStateBuffer )
            
            const mockPKCEPair = {
                codeVerifier: 'test-code-verifier',
                codeChallenge: 'test-code-challenge',
                codeChallengeMethod: 'S256'
            }
            mockPKCEGenerator.generatePKCEPair.mockReturnValue( { pair: mockPKCEPair } )

            const result = flowHandler.initiateAuthorizationCodeFlow( {} )

            expect( mockCrypto.randomBytes ).toHaveBeenCalledWith( 16 )
            expect( mockPKCEGenerator.generatePKCEPair ).toHaveBeenCalled()

            expect( result ).toEqual( {
                authorizationUrl: expect.stringContaining( 'http://localhost:8080/realms/test-realm/protocol/openid-connect/auth' ),
                state: mockStateBuffer.toString( 'base64url' )
            } )

            expect( result.authorizationUrl ).toContain( 'response_type=code' )
            expect( result.authorizationUrl ).toContain( 'client_id=test-client' )
            expect( result.authorizationUrl ).toContain( 'scope=openid' )
            expect( result.authorizationUrl ).toContain( 'code_challenge=test-code-challenge' )
            expect( result.authorizationUrl ).toContain( 'code_challenge_method=S256' )
        } )

        test( 'generates authorization URL with custom scopes and resource indicators', () => {
            const mockStateBuffer = Buffer.from( 'custom-state' )
            mockCrypto.randomBytes.mockReturnValue( mockStateBuffer )
            
            const mockPKCEPair = {
                codeVerifier: 'verifier',
                codeChallenge: 'challenge',
                codeChallengeMethod: 'S256'
            }
            mockPKCEGenerator.generatePKCEPair.mockReturnValue( { pair: mockPKCEPair } )

            const result = flowHandler.initiateAuthorizationCodeFlow( {
                scopes: [ 'openid', 'profile', 'mcp:tools' ],
                resourceIndicators: [ 'https://api.example.com', 'https://api2.example.com' ]
            } )

            expect( result.authorizationUrl ).toContain( 'scope=openid+profile+mcp%3Atools' )
            expect( result.authorizationUrl ).toContain( 'resource=https%3A%2F%2Fapi.example.com+https%3A%2F%2Fapi2.example.com' )
        } )

        test( 'logs authorization URL when silent is false', () => {
            const consoleSpy = jest.spyOn( console, 'log' ).mockImplementation()
            
            const verboseHandler = OAuthFlowHandler.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'test-client',
                redirectUri: 'http://localhost:3000/callback',
                silent: false
            } )

            mockCrypto.randomBytes.mockReturnValue( Buffer.from( 'log-state' ) )
            mockPKCEGenerator.generatePKCEPair.mockReturnValue( {
                pair: {
                    codeVerifier: 'verifier',
                    codeChallenge: 'challenge',
                    codeChallengeMethod: 'S256'
                }
            } )

            verboseHandler.initiateAuthorizationCodeFlow( {} )

            expect( consoleSpy ).toHaveBeenCalledWith( 
                expect.stringContaining( 'Authorization URL:' ) 
            )

            consoleSpy.mockRestore()
        } )
    } )

    describe( 'handleAuthorizationCallback', () => {
        test( 'handles valid authorization callback', async () => {
            const mockStateBuffer = Buffer.from( 'valid-state' )
            mockCrypto.randomBytes.mockReturnValue( mockStateBuffer )
            
            const mockPKCEPair = {
                codeVerifier: 'test-verifier',
                codeChallenge: 'test-challenge',
                codeChallengeMethod: 'S256'
            }
            mockPKCEGenerator.generatePKCEPair.mockReturnValue( { pair: mockPKCEPair } )

            // First initiate a flow to create state
            const { state } = flowHandler.initiateAuthorizationCodeFlow( {} )

            const mockTokenResponse = {
                access_token: 'access-token-123',
                token_type: 'Bearer',
                expires_in: 3600,
                refresh_token: 'refresh-token-456'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockTokenResponse )
            } )

            const result = await flowHandler.handleAuthorizationCallback( {
                code: 'authorization-code-123',
                state
            } )

            expect( mockFetch ).toHaveBeenCalledWith(
                'http://localhost:8080/realms/test-realm/protocol/openid-connect/token',
                expect.objectContaining( {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                } )
            )

            expect( result ).toEqual( {
                success: true,
                tokens: mockTokenResponse
            } )
        } )

        test( 'rejects callback with invalid state', async () => {
            const result = await flowHandler.handleAuthorizationCallback( {
                code: 'authorization-code-123',
                state: 'invalid-state'
            } )

            expect( result ).toEqual( {
                success: false,
                error: 'Invalid state parameter'
            } )

            expect( mockFetch ).not.toHaveBeenCalled()
        } )
    } )

    describe( 'requestClientCredentials', () => {
        test( 'requests client credentials without scopes', async () => {
            const mockTokenResponse = {
                access_token: 'client-credentials-token',
                token_type: 'Bearer',
                expires_in: 3600
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockTokenResponse )
            } )

            const result = await flowHandler.requestClientCredentials( {} )

            expect( mockFetch ).toHaveBeenCalledWith(
                'http://localhost:8080/realms/test-realm/protocol/openid-connect/token',
                expect.objectContaining( {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                } )
            )

            const sentBody = mockFetch.mock.calls[0][1].body
            expect( sentBody.toString() ).toContain( 'grant_type=client_credentials' )
            expect( sentBody.toString() ).toContain( 'client_id=test-client' )
            expect( sentBody.toString() ).toContain( 'client_secret=test-secret' )

            expect( result ).toEqual( {
                tokens: mockTokenResponse
            } )
        } )

        test( 'requests client credentials with custom scopes', async () => {
            const mockTokenResponse = {
                access_token: 'scoped-token',
                scope: 'mcp:tools mcp:resources'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockTokenResponse )
            } )

            const result = await flowHandler.requestClientCredentials( {
                scopes: [ 'mcp:tools', 'mcp:resources' ]
            } )

            const sentBody = mockFetch.mock.calls[0][1].body
            expect( sentBody.toString() ).toContain( 'scope=mcp%3Atools+mcp%3Aresources' )

            expect( result.tokens ).toEqual( mockTokenResponse )
        } )

        test( 'logs success message when silent is false', async () => {
            const consoleSpy = jest.spyOn( console, 'log' ).mockImplementation()
            
            const verboseHandler = OAuthFlowHandler.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'test-client',
                clientSecret: 'test-secret',
                silent: false
            } )

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( { access_token: 'token' } )
            } )

            await verboseHandler.requestClientCredentials( {} )

            expect( consoleSpy ).toHaveBeenCalledWith( 'Client credentials obtained successfully' )

            consoleSpy.mockRestore()
        } )
    } )

    describe( 'refreshAccessToken', () => {
        test( 'refreshes access token successfully', async () => {
            const mockTokenResponse = {
                access_token: 'new-access-token',
                token_type: 'Bearer',
                expires_in: 3600,
                refresh_token: 'new-refresh-token'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockTokenResponse )
            } )

            const result = await flowHandler.refreshAccessToken( {
                refreshToken: 'old-refresh-token'
            } )

            expect( mockFetch ).toHaveBeenCalledWith(
                'http://localhost:8080/realms/test-realm/protocol/openid-connect/token',
                expect.objectContaining( {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                } )
            )

            const sentBody = mockFetch.mock.calls[0][1].body
            expect( sentBody.toString() ).toContain( 'grant_type=refresh_token' )
            expect( sentBody.toString() ).toContain( 'refresh_token=old-refresh-token' )
            expect( sentBody.toString() ).toContain( 'client_id=test-client' )
            expect( sentBody.toString() ).toContain( 'client_secret=test-secret' )

            expect( result ).toEqual( {
                success: true,
                tokens: mockTokenResponse
            } )
        } )

        test( 'handles refresh token error', async () => {
            const mockErrorResponse = {
                error: 'invalid_grant',
                error_description: 'Refresh token has expired'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockErrorResponse )
            } )

            const result = await flowHandler.refreshAccessToken( {
                refreshToken: 'expired-refresh-token'
            } )

            expect( result ).toEqual( {
                success: false,
                error: 'Refresh token has expired'
            } )
        } )

        test( 'handles refresh token error without description', async () => {
            const mockErrorResponse = {
                error: 'server_error'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockErrorResponse )
            } )

            const result = await flowHandler.refreshAccessToken( {
                refreshToken: 'token'
            } )

            expect( result ).toEqual( {
                success: false,
                error: 'Token refresh failed'
            } )
        } )
    } )

    describe( 'code exchange (private method)', () => {
        test( 'exchanges code for tokens with client secret', async () => {
            const mockStateBuffer = Buffer.from( 'exchange-state' )
            mockCrypto.randomBytes.mockReturnValue( mockStateBuffer )
            
            const mockPKCEPair = {
                codeVerifier: 'exchange-verifier',
                codeChallenge: 'exchange-challenge',
                codeChallengeMethod: 'S256'
            }
            mockPKCEGenerator.generatePKCEPair.mockReturnValue( { pair: mockPKCEPair } )

            const { state } = flowHandler.initiateAuthorizationCodeFlow( {} )

            const mockTokenResponse = {
                access_token: 'exchanged-token',
                token_type: 'Bearer'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockTokenResponse )
            } )

            await flowHandler.handleAuthorizationCallback( {
                code: 'auth-code',
                state
            } )

            const sentBody = mockFetch.mock.calls[0][1].body
            expect( sentBody.toString() ).toContain( 'grant_type=authorization_code' )
            expect( sentBody.toString() ).toContain( 'code=auth-code' )
            expect( sentBody.toString() ).toContain( 'redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback' )
            expect( sentBody.toString() ).toContain( 'client_id=test-client' )
            expect( sentBody.toString() ).toContain( 'code_verifier=exchange-verifier' )
            expect( sentBody.toString() ).toContain( 'client_secret=test-secret' )
        } )

        test( 'exchanges code for tokens without client secret', async () => {
            const publicHandler = OAuthFlowHandler.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'public-client',
                redirectUri: 'http://localhost:3000/callback',
                silent: true
            } )

            mockCrypto.randomBytes.mockReturnValue( Buffer.from( 'public-state' ) )
            mockPKCEGenerator.generatePKCEPair.mockReturnValue( {
                pair: {
                    codeVerifier: 'public-verifier',
                    codeChallenge: 'public-challenge',
                    codeChallengeMethod: 'S256'
                }
            } )

            const { state } = publicHandler.initiateAuthorizationCodeFlow( {} )

            const mockTokenResponse = {
                access_token: 'public-token'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockTokenResponse )
            } )

            await publicHandler.handleAuthorizationCallback( {
                code: 'public-code',
                state
            } )

            const sentBody = mockFetch.mock.calls[0][1].body
            expect( sentBody.toString() ).toContain( 'client_id=public-client' )
            expect( sentBody.toString() ).not.toContain( 'client_secret' )
        } )
    } )
} )