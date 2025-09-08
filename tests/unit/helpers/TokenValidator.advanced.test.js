import { jest } from '@jest/globals'

// Mock JWT library
const mockJwt = {
    verify: jest.fn()
}

// Mock JWKS client
const mockJwksClient = {
    getSigningKey: jest.fn()
}

jest.unstable_mockModule( 'jsonwebtoken', () => ({
    default: mockJwt
}) )
jest.unstable_mockModule( 'jwks-client', () => ({
    default: jest.fn().mockReturnValue( mockJwksClient )
}) )

const { TokenValidator } = await import( '../../../src/helpers/TokenValidator.mjs' )


describe( 'TokenValidator - Advanced Coverage Tests', () => {

    let validator
    
    const testConfig = {
        realmsByRoute: {
            '/api': {
                providerUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client',
                clientSecret: 'test-secret',
                issuer: 'https://auth.example.com',
                jwksUrl: 'https://auth.example.com/.well-known/jwks.json'
            }
        },
        silent: true
    }

    beforeEach( () => {
        jest.clearAllMocks()
        validator = TokenValidator.createForMultiRealm( testConfig )
    } )


    describe( 'Token Validation with Caching', () => {

        test( 'validateForRoute with cache miss - calls JWT verify', async () => {
            const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
            
            // Mock successful JWT verification
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( null, { 
                    sub: 'user123', 
                    iss: 'https://auth.example.com',
                    aud: 'test-client'
                } )
            } )

            const result = await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            expect( result.isValid ).toBe( true )
            expect( result.decoded.sub ).toBe( 'user123' )
            expect( mockJwt.verify ).toHaveBeenCalled()
        } )


        test( 'validateForRoute with cache hit - skips JWT verify', async () => {
            const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
            
            // First call - cache miss
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( null, { 
                    sub: 'user123', 
                    iss: 'https://auth.example.com',
                    aud: 'test-client'
                } )
            } )

            await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            // Clear mock call count
            mockJwt.verify.mockClear()

            // Second call - should hit cache
            const result = await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            expect( result.isValid ).toBe( true )
            expect( result.decoded.sub ).toBe( 'user123' )
            // Should not call JWT verify again due to cache hit
            expect( mockJwt.verify ).not.toHaveBeenCalled()
        } )


        test( 'validateForRoute with expired cache - calls JWT verify again', async () => {
            const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
            
            // Mock JWT verification
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( null, { 
                    sub: 'user123', 
                    iss: 'https://auth.example.com',
                    aud: 'test-client'
                } )
            } )

            // First validation
            await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            // Mock time passing (more than 2 minutes = 120000ms)
            const originalDateNow = Date.now
            Date.now = jest.fn().mockReturnValue( originalDateNow() + 130000 )

            mockJwt.verify.mockClear()

            // Second validation - cache should be expired
            const result = await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            expect( result.isValid ).toBe( true )
            expect( mockJwt.verify ).toHaveBeenCalled()

            // Restore Date.now
            Date.now = originalDateNow
        } )

    } )


    describe( 'JWT Verification Error Handling', () => {

        test( 'handles JWT verification error', async () => {
            const mockToken = 'invalid.jwt.token'
            
            // Mock JWT verification error
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( new Error( 'Token expired' ), null )
            } )

            const result = await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            expect( result.isValid ).toBe( false )
            expect( result.error ).toBe( 'Token expired' )
        } )


        test( 'handles JWKS key retrieval error', async () => {
            const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
            
            // Mock JWT verification that calls getKey callback
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                // Simulate getKey callback with error
                getKey( { kid: 'test-key-id' }, ( err, key ) => {
                    // This should trigger the error path in getKeyForRoute
                    expect( err ).toBeDefined()
                } )
                callback( new Error( 'Unable to find a signing key' ), null )
            } )

            // Mock JWKS client error
            mockJwksClient.getSigningKey.mockImplementation( ( kid, callback ) => {
                callback( new Error( 'JWKS endpoint unavailable' ) )
            } )

            const result = await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            expect( result.isValid ).toBe( false )
            expect( result.error ).toContain( 'signing key' )
        } )


        test( 'handles successful JWKS key retrieval', async () => {
            const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
            
            // Mock JWKS client success
            mockJwksClient.getSigningKey.mockImplementation( ( kid, callback ) => {
                callback( null, { 
                    publicKey: '-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----'
                } )
            } )

            // Mock JWT verification success
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                // Test the getKey callback
                getKey( { kid: 'test-key-id' }, ( err, key ) => {
                    expect( err ).toBeNull()
                    expect( key ).toBe( '-----BEGIN PUBLIC KEY-----\nMOCK_KEY\n-----END PUBLIC KEY-----' )
                } )
                callback( null, { 
                    sub: 'user123', 
                    iss: 'https://auth.example.com',
                    aud: 'test-client'
                } )
            } )

            const result = await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            expect( result.isValid ).toBe( true )
        } )


        test( 'handles JWKS key with rsaPublicKey fallback', async () => {
            const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
            
            // Mock JWKS client returning rsaPublicKey instead of publicKey
            mockJwksClient.getSigningKey.mockImplementation( ( kid, callback ) => {
                callback( null, { 
                    rsaPublicKey: '-----BEGIN RSA PUBLIC KEY-----\nMOCK_RSA_KEY\n-----END RSA PUBLIC KEY-----'
                } )
            } )

            // Mock JWT verification success
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                getKey( { kid: 'test-key-id' }, ( err, key ) => {
                    expect( err ).toBeNull()
                    expect( key ).toBe( '-----BEGIN RSA PUBLIC KEY-----\nMOCK_RSA_KEY\n-----END RSA PUBLIC KEY-----' )
                } )
                callback( null, { 
                    sub: 'user123', 
                    iss: 'https://auth.example.com',
                    aud: 'test-client'
                } )
            } )

            const result = await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            expect( result.isValid ).toBe( true )
        } )

    } )


    describe( 'Error Path Coverage', () => {

        test( 'getConfigForRoute throws error for invalid route', () => {
            expect( () => {
                validator.getAllRoutes() // This internally calls getConfigForRoute
                // Actually, let's test a private method indirectly
                // We need to trigger the error path
            } ).not.toThrow() // This method exists and should work

            // Test validation with invalid route - should trigger error path
            expect( async () => {
                await validator.validateForRoute( { 
                    token: 'test.token.here', 
                    route: '/nonexistent' 
                } )
            } ).rejects.toThrow( 'No configuration found for route: /nonexistent' )
        } )


        test( 'processValidationResult handles invalid token', () => {
            const mockToken = 'invalid.token'
            
            // Mock JWT verification that returns error - this will make isValid false
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( new Error( 'Invalid token' ), null )
            } )

            return validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } ).then( result => {
                expect( result.isValid ).toBe( false )
            } )
        } )

    } )


    describe( 'Validation Result Processing', () => {

        test( 'processes successful validation result with caching', async () => {
            const mockToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
            const mockDecoded = { 
                sub: 'user123', 
                iss: 'https://auth.example.com',
                aud: 'test-client',
                exp: Math.floor( Date.now() / 1000 ) + 3600,
                iat: Math.floor( Date.now() / 1000 ),
                scope: 'read write'
            }
            
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( null, mockDecoded )
            } )

            const result = await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            expect( result ).toMatchObject( {
                isValid: true,
                decoded: mockDecoded,
                route: '/api'
            } )
        } )


        test( 'processes failed validation result without caching', async () => {
            const mockToken = 'invalid.token'
            
            mockJwt.verify.mockImplementation( ( token, getKey, options, callback ) => {
                callback( new Error( 'Invalid signature' ), null )
            } )

            const result = await validator.validateForRoute( { 
                token: mockToken, 
                route: '/api' 
            } )

            expect( result ).toMatchObject( {
                isValid: false,
                error: 'Invalid signature',
                route: '/api'
            } )
        } )

    } )

} )