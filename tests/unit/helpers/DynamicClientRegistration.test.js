import { jest } from '@jest/globals'
import { TestUtils } from '../../helpers/utils.mjs'

const mockFetch = jest.fn()

// Mock native fetch (Node.js 22+)
global.fetch = mockFetch

const { DynamicClientRegistration } = await import( '../../../src/helpers/DynamicClientRegistration.mjs' )

// Test configuration using .auth.env.example
const config = {
    envPath: '../../../.auth.env.example',
    providerUrl: 'https://your-first-auth0-domain.auth0.com',
    realm: 'test-realm',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    silent: true
}


describe( 'DynamicClientRegistration', () => {
    let registration
    
    beforeEach( () => {
        registration = DynamicClientRegistration.create( {
            keycloakUrl: config.providerUrl,
            realm: config.realm,
            silent: config.silent
        } )
        
        mockFetch.mockClear()
    } )

    afterEach( () => {
        jest.resetAllMocks()
    } )

    describe( 'create', () => {
        test( 'creates DynamicClientRegistration instance with valid configuration', () => {
            const client = DynamicClientRegistration.create( {
                keycloakUrl: config.providerUrl,
                realm: config.realm
            } )

            expect( client ).toBeDefined()
            expect( typeof client.registerClient ).toBe( 'function' )
            expect( typeof client.updateClient ).toBe( 'function' )
            expect( typeof client.deleteClient ).toBe( 'function' )
        } )
    } )

    describe( 'registerClient', () => {
        test( 'registers client successfully with minimal parameters', async () => {
            const mockResponse = {
                client_id: 'new-client-123',
                client_secret: 'secret-456',
                registration_access_token: 'token-789',
                registration_client_uri: 'http://localhost:8080/realms/test-realm/clients/new-client-123'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockResponse )
            } )

            const result = await registration.registerClient( {
                clientName: 'Test Client',
                redirectUris: [ 'http://localhost:3000/callback' ]
            } )

            expect( mockFetch ).toHaveBeenCalledWith(
                `${config.providerUrl}/realms/${config.realm}/clients-registrations/openid-connect`,
                expect.objectContaining( {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: expect.stringContaining( 'Test Client' )
                } )
            )

            expect( result ).toEqual( {
                success: true,
                clientId: 'new-client-123',
                clientSecret: 'secret-456',
                registrationAccessToken: 'token-789',
                registrationClientUri: 'http://localhost:8080/realms/test-realm/clients/new-client-123',
                metadata: mockResponse
            } )
        } )

        test( 'registers client with all optional parameters', async () => {
            const mockResponse = {
                client_id: 'new-client-456',
                client_secret: 'secret-789'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockResponse )
            } )

            const result = await registration.registerClient( {
                clientName: 'Full Test Client',
                redirectUris: [ 'http://localhost:3000/callback' ],
                grantTypes: [ 'authorization_code', 'client_credentials' ],
                responseTypes: [ 'code' ],
                tokenEndpointAuthMethod: 'client_secret_basic',
                applicationName: 'My MCP App',
                contacts: [ 'admin@example.com' ],
                logoUri: 'https://example.com/logo.png',
                policyUri: 'https://example.com/policy',
                tosUri: 'https://example.com/terms'
            } )

            const sentBody = JSON.parse( mockFetch.mock.calls[0][1].body )
            expect( sentBody ).toEqual( {
                client_name: 'Full Test Client',
                redirect_uris: [ 'http://localhost:3000/callback' ],
                grant_types: [ 'authorization_code', 'client_credentials' ],
                response_types: [ 'code' ],
                token_endpoint_auth_method: 'client_secret_basic',
                application_type: 'native',
                require_auth_time: false,
                default_max_age: 3600,
                application_name: 'My MCP App',
                contacts: [ 'admin@example.com' ],
                logo_uri: 'https://example.com/logo.png',
                policy_uri: 'https://example.com/policy',
                tos_uri: 'https://example.com/terms'
            } )

            expect( result.success ).toBe( true )
            expect( result.clientId ).toBe( 'new-client-456' )
        } )

        test( 'handles registration error from server', async () => {
            const mockErrorResponse = {
                error: 'invalid_client_metadata',
                error_description: 'Invalid redirect URI'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockErrorResponse )
            } )

            const result = await registration.registerClient( {
                clientName: 'Test Client',
                redirectUris: [ 'invalid-uri' ]
            } )

            expect( result ).toEqual( {
                success: false,
                error: 'Invalid redirect URI'
            } )
        } )

        test( 'handles registration error without description', async () => {
            const mockErrorResponse = {
                error: 'server_error'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockErrorResponse )
            } )

            const result = await registration.registerClient( {
                clientName: 'Test Client'
            } )

            expect( result ).toEqual( {
                success: false,
                error: 'Registration failed'
            } )
        } )

        test( 'logs success message when silent is false', async () => {
            const consoleSpy = jest.spyOn( console, 'log' ).mockImplementation()
            
            const verboseRegistration = DynamicClientRegistration.create( {
                keycloakUrl: config.providerUrl,
                realm: 'test-realm',
                silent: false
            } )

            const mockResponse = {
                client_id: 'new-client-log',
                client_secret: 'secret-log'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockResponse )
            } )

            await verboseRegistration.registerClient( {
                clientName: 'Test Client'
            } )

            expect( consoleSpy ).toHaveBeenCalledWith( '✅Client registered successfully: new-client-log' )

            consoleSpy.mockRestore()
        } )
    } )

    describe( 'updateClient', () => {
        test( 'updates client successfully', async () => {
            const mockResponse = {
                client_id: 'client-123',
                client_name: 'Updated Client Name'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockResponse )
            } )

            const result = await registration.updateClient( {
                clientId: 'client-123',
                registrationAccessToken: 'access-token',
                updates: {
                    client_name: 'Updated Client Name'
                }
            } )

            expect( mockFetch ).toHaveBeenCalledWith(
                `${config.providerUrl}/realms/${config.realm}/clients-registrations/openid-connect/client-123`,
                expect.objectContaining( {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer access-token'
                    }
                } )
            )

            expect( result ).toEqual( {
                success: true,
                metadata: mockResponse
            } )
        } )

        test( 'handles update error from server', async () => {
            const mockErrorResponse = {
                error: 'invalid_token',
                error_description: 'Registration access token is invalid'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockErrorResponse )
            } )

            const result = await registration.updateClient( {
                clientId: 'client-123',
                registrationAccessToken: 'invalid-token',
                updates: {}
            } )

            expect( result ).toEqual( {
                success: false,
                error: 'Registration access token is invalid'
            } )
        } )

        test( 'handles update error without description', async () => {
            const mockErrorResponse = {
                error: 'server_error'
            }

            mockFetch.mockResolvedValueOnce( {
                json: jest.fn().mockResolvedValue( mockErrorResponse )
            } )

            const result = await registration.updateClient( {
                clientId: 'client-123',
                registrationAccessToken: 'token',
                updates: {}
            } )

            expect( result ).toEqual( {
                success: false,
                error: 'Update failed'
            } )
        } )
    } )

    describe( 'deleteClient', () => {
        test( 'deletes client successfully', async () => {
            mockFetch.mockResolvedValueOnce( {
                status: 204
            } )

            const result = await registration.deleteClient( {
                clientId: 'client-123',
                registrationAccessToken: 'access-token'
            } )

            expect( mockFetch ).toHaveBeenCalledWith(
                `${config.providerUrl}/realms/${config.realm}/clients-registrations/openid-connect/client-123`,
                expect.objectContaining( {
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer access-token'
                    }
                } )
            )

            expect( result ).toEqual( { success: true } )
        } )

        test( 'handles deletion failure', async () => {
            mockFetch.mockResolvedValueOnce( {
                status: 401
            } )

            const result = await registration.deleteClient( {
                clientId: 'client-123',
                registrationAccessToken: 'invalid-token'
            } )

            expect( result ).toEqual( {
                success: false,
                error: 'Deletion failed'
            } )
        } )

        test( 'logs success message when silent is false', async () => {
            const consoleSpy = jest.spyOn( console, 'log' ).mockImplementation()
            
            const verboseRegistration = DynamicClientRegistration.create( {
                keycloakUrl: config.providerUrl,
                realm: 'test-realm',
                silent: false
            } )

            mockFetch.mockResolvedValueOnce( {
                status: 204
            } )

            await verboseRegistration.deleteClient( {
                clientId: 'client-log',
                registrationAccessToken: 'access-token'
            } )

            expect( consoleSpy ).toHaveBeenCalledWith( '✅Client client-log deleted successfully' )

            consoleSpy.mockRestore()
        } )
    } )
} )