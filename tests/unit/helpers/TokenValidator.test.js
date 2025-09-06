import { jest } from '@jest/globals'

const mockJwt = {
    verify: jest.fn()
}

const mockJwksClient = jest.fn()

jest.unstable_mockModule( 'jsonwebtoken', () => ({
    default: mockJwt
}) )

jest.unstable_mockModule( 'jwks-client', () => ({
    default: mockJwksClient
}) )

const { TokenValidator } = await import( '../../../src/helpers/TokenValidator.mjs' )

describe( 'TokenValidator', () => {
    let tokenValidator
    let mockJwksClientInstance

    beforeEach( () => {
        mockJwksClientInstance = {
            getSigningKey: jest.fn()
        }

        mockJwksClient.mockReturnValue( mockJwksClientInstance )

        tokenValidator = TokenValidator.create( {
            keycloakUrl: 'http://localhost:8080',
            realm: 'test-realm',
            clientId: 'test-client',
            silent: true
        } )
    } )

    afterEach( () => {
        jest.resetAllMocks()
    } )

    describe( 'create', () => {
        test( 'creates TokenValidator instance with valid configuration', () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'test-client'
            } )

            expect( validator ).toBeDefined()
            expect( typeof validator.validate ).toBe( 'function' )
        } )
    } )

    describe( 'validate', () => {
        test( 'validates token successfully', async () => {
            const mockDecoded = {
                sub: 'user123',
                scope: 'mcp:tools',
                iat: Math.floor( Date.now() / 1000 ),
                exp: Math.floor( Date.now() / 1000 ) + 3600
            }

            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( null, mockDecoded )
            } )

            mockJwksClientInstance.getSigningKey.mockImplementation( ( kid, callback ) => {
                callback( null, { publicKey: 'mock-public-key' } )
            } )

            const result = await tokenValidator.validate( { token: 'valid-token' } )

            expect( result.isValid ).toBe( true )
            expect( result.decoded ).toEqual( mockDecoded )
            expect( result.error ).toBeNull()
        } )

        test( 'handles invalid token', async () => {
            const mockError = new Error( 'Token expired' )

            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( mockError, null )
            } )

            const result = await tokenValidator.validate( { token: 'invalid-token' } )

            expect( result.isValid ).toBe( false )
            expect( result.decoded ).toBeNull()
            expect( result.error ).toBe( 'Token expired' )
        } )

        test( 'handles JWKS key retrieval error', async () => {
            const mockJwksError = new Error( 'Unable to find key' )

            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                getKey( { kid: 'test-kid' }, ( err ) => {
                    callback( err )
                } )
            } )

            mockJwksClientInstance.getSigningKey.mockImplementation( ( kid, callback ) => {
                callback( mockJwksError, null )
            } )

            const result = await tokenValidator.validate( { token: 'token-with-unknown-kid' } )

            expect( result.isValid ).toBe( false )
            expect( result.error ).toBe( 'Unable to find key' )
        } )
    } )

    describe( 'validateScopes', () => {
        test( 'validates required scopes successfully', () => {
            const mockDecoded = {
                sub: 'user123',
                scope: 'mcp:tools mcp:resources openid'
            }

            tokenValidator.validate = jest.fn().mockReturnValue( {
                isValid: true,
                decoded: mockDecoded
            } )

            const result = tokenValidator.validateScopes( {
                token: 'valid-token',
                requiredScopes: [ 'mcp:tools', 'openid' ]
            } )

            expect( result.hasRequiredScopes ).toBe( true )
            expect( result.missingScopes ).toEqual( [] )
            expect( result.availableScopes ).toEqual( [ 'mcp:tools', 'mcp:resources', 'openid' ] )
        } )

        test( 'identifies missing scopes', () => {
            const mockDecoded = {
                sub: 'user123',
                scope: 'mcp:tools openid'
            }

            tokenValidator.validate = jest.fn().mockReturnValue( {
                isValid: true,
                decoded: mockDecoded
            } )

            const result = tokenValidator.validateScopes( {
                token: 'valid-token',
                requiredScopes: [ 'mcp:tools', 'mcp:resources', 'admin' ]
            } )

            expect( result.hasRequiredScopes ).toBe( false )
            expect( result.missingScopes ).toEqual( [ 'mcp:resources', 'admin' ] )
            expect( result.availableScopes ).toEqual( [ 'mcp:tools', 'openid' ] )
        } )

        test( 'handles token without scopes', () => {
            const mockDecoded = {
                sub: 'user123'
            }

            tokenValidator.validate = jest.fn().mockReturnValue( {
                isValid: true,
                decoded: mockDecoded
            } )

            const result = tokenValidator.validateScopes( {
                token: 'valid-token',
                requiredScopes: [ 'mcp:tools' ]
            } )

            expect( result.hasRequiredScopes ).toBe( false )
            expect( result.missingScopes ).toEqual( [ 'mcp:tools' ] )
            expect( result.availableScopes ).toEqual( [] )
        } )

        test( 'handles invalid token in validateScopes', () => {
            tokenValidator.validate = jest.fn().mockReturnValue( {
                isValid: false,
                decoded: null
            } )

            const result = tokenValidator.validateScopes( {
                token: 'invalid-token',
                requiredScopes: [ 'mcp:tools' ]
            } )

            expect( result.hasRequiredScopes ).toBe( false )
            expect( result.missingScopes ).toEqual( [ 'mcp:tools' ] )
        } )

        test( 'handles RSA public key in getKey callback', async () => {
            const mockDecoded = {
                sub: 'user123',
                scope: 'mcp:tools'
            }

            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                getKey( { kid: 'test-kid' }, ( err, key ) => {
                    expect( key ).toBe( 'rsa-key' )
                    callback( null, mockDecoded )
                } )
            } )

            mockJwksClientInstance.getSigningKey.mockImplementation( ( kid, callback ) => {
                callback( null, { rsaPublicKey: 'rsa-key' } )
            } )

            const result = await tokenValidator.validate( { token: 'valid-token' } )

            expect( result.isValid ).toBe( true )
        } )

        test( 'handles silent mode logging', async () => {
            const consoleSpy = jest.spyOn( console, 'log' ).mockImplementation()
            
            const validator = TokenValidator.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'test-client',
                silent: false
            } )

            const mockDecoded = { sub: 'user123' }

            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( null, mockDecoded )
            } )

            await validator.validate( { token: 'valid-token' } )

            expect( consoleSpy ).toHaveBeenCalledWith( 'Token validation successful' )

            consoleSpy.mockRestore()
        } )

        test( 'handles silent mode logging for errors', async () => {
            const consoleSpy = jest.spyOn( console, 'log' ).mockImplementation()
            
            const validator = TokenValidator.create( {
                keycloakUrl: 'http://localhost:8080',
                realm: 'test-realm',
                clientId: 'test-client',
                silent: false
            } )

            const mockError = new Error( 'Token expired' )

            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( mockError, null )
            } )

            await validator.validate( { token: 'invalid-token' } )

            expect( consoleSpy ).toHaveBeenCalledWith( 'Token validation failed: Token expired' )

            consoleSpy.mockRestore()
        } )
    } )
} )