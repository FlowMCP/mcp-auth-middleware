import { jest } from '@jest/globals'

const mockFetch = jest.fn()

jest.unstable_mockModule( 'node-fetch', () => ({
    default: mockFetch
}) )

const { KeycloakClient } = await import( '../../../src/helpers/KeycloakClient.mjs' )

describe( 'KeycloakClient', () => {
    let keycloakClient
    
    beforeEach( () => {
        keycloakClient = KeycloakClient.create( {
            keycloakUrl: 'http://localhost:8080',
            realm: 'test-realm',
            clientId: 'test-client',
            clientSecret: 'test-secret',
            silent: true
        } )
        
        mockFetch.mockClear()
    } )

    afterEach( () => {
        jest.resetAllMocks()
    } )

    describe( 'create', () => {
        test( 'creates KeycloakClient instance with valid configuration', () => {
            const client = KeycloakClient.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'test-client',
                clientSecret: 'test-secret'
            } )

            expect( client ).toBeDefined()
            expect( typeof client.getJwks ).toBe( 'function' )
        } )
    } )

    describe( 'getJwks', () => {
        test( 'retrieves JWKS data from Keycloak', async () => {
            const mockJwksData = {
                keys: [
                    {
                        kid: 'test-key-id',
                        kty: 'RSA',
                        alg: 'RS256'
                    }
                ]
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockJwksData )
            } )

            const { jwksData } = await keycloakClient.getJwks()

            expect( mockFetch ).toHaveBeenCalledWith(
                'http://localhost:8080/realms/test-realm/protocol/openid-connect/certs'
            )
            expect( jwksData ).toEqual( mockJwksData )
        } )
    } )

    describe( 'validateToken', () => {
        test( 'validates token successfully', async () => {
            const mockTokenData = {
                active: true,
                sub: 'user123',
                scope: 'mcp:tools'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockTokenData )
            } )

            const { isValid, tokenData } = await keycloakClient.validateToken( { 
                token: 'test-token' 
            } )

            expect( isValid ).toBe( true )
            expect( tokenData ).toEqual( mockTokenData )
            expect( mockFetch ).toHaveBeenCalledWith(
                'http://localhost:8080/realms/test-realm/protocol/openid-connect/token/introspect',
                expect.objectContaining( {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                } )
            )
        } )

        test( 'handles invalid token', async () => {
            const mockTokenData = {
                active: false
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockTokenData )
            } )

            const { isValid, tokenData } = await keycloakClient.validateToken( { 
                token: 'invalid-token' 
            } )

            expect( isValid ).toBe( false )
            expect( tokenData ).toEqual( mockTokenData )
        } )
    } )

    describe( 'getRealmInfo', () => {
        test( 'retrieves realm information with admin token', async () => {
            const mockAdminToken = 'admin-access-token'
            const mockRealmData = {
                realm: 'test-realm',
                enabled: true
            }

            mockFetch
                .mockResolvedValueOnce( {
                    json: jest.fn().mockResolvedValue( { access_token: mockAdminToken } )
                } )
                .mockResolvedValueOnce( {
                    json: jest.fn().mockResolvedValue( mockRealmData )
                } )

            const { realmData } = await keycloakClient.getRealmInfo()

            expect( realmData ).toEqual( mockRealmData )
            expect( mockFetch ).toHaveBeenCalledTimes( 2 )
        } )
    } )

    describe( 'silent logging', () => {
        test( 'logs JWKS retrieval when silent is false', async () => {
            const consoleSpy = jest.spyOn( console, 'log' ).mockImplementation()
            
            const client = KeycloakClient.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'test-client',
                clientSecret: 'test-secret',
                silent: false
            } )

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( { keys: [] } )
            } )

            await client.getJwks()

            expect( consoleSpy ).toHaveBeenCalledWith( 
                'JWKS retrieved from: http://localhost:8080/realms/test-realm/protocol/openid-connect/certs' 
            )

            consoleSpy.mockRestore()
        } )
    } )
} )