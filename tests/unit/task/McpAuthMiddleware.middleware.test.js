import { jest } from '@jest/globals'
import express from 'express'
import request from 'supertest'

// Mock all dependencies
const mockTokenValidator = {
    validateForRoute: jest.fn(),
    validateScopesForRoute: jest.fn(),
    validateWithAudienceBinding: jest.fn()
}
const mockOAuthFlowHandler = {
    initiateAuthorizationCodeFlowForRoute: jest.fn().mockReturnValue({
        authorizationUrl: 'https://tenant.auth0.com/authorize?client_id=test',
        state: 'mock-state-123',
        route: '/api'
    }),
    handleAuthorizationCallbackForRoute: jest.fn(),
    getDiscoveryData: jest.fn().mockReturnValue({
        issuer: 'https://tenant.auth0.com',
        authorization_endpoint: 'https://tenant.auth0.com/authorize',
        token_endpoint: 'https://tenant.auth0.com/oauth/token'
    })
}

const mockAuthTypeHandler = {
    provider: {
        normalizeConfiguration: jest.fn().mockReturnValue({ normalizedConfig: {} }),
        generateEndpoints: jest.fn().mockReturnValue({ endpoints: {} })
    },
    tokenValidator: mockTokenValidator,
    flowHandler: mockOAuthFlowHandler,
    config: {}
}

jest.unstable_mockModule( '../../../src/core/AuthTypeFactory.mjs', () => ({
    AuthTypeFactory: {
        createAuthHandler: jest.fn().mockReturnValue( mockAuthTypeHandler )
    }
}) )

jest.unstable_mockModule( '../../../src/helpers/TokenValidator.mjs', () => ({
    TokenValidator: {
        createForMultiRealm: jest.fn().mockReturnValue( mockTokenValidator )
    }
}) )

jest.unstable_mockModule( '../../../src/helpers/OAuthFlowHandler.mjs', () => ({
    OAuthFlowHandler: {
        createForMultiRealm: jest.fn().mockReturnValue( mockOAuthFlowHandler )
    }
}) )

const { McpAuthMiddleware } = await import( '../../../src/index.mjs' )


describe( 'McpAuthMiddleware - Express Middleware Logic', () => {
    
    let app
    let middleware
    
    const testConfig = {
        '/api': {
            authType: 'oauth21_auth0',
            providerUrl: 'https://tenant.auth0.com',
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            scope: 'openid profile email api:read',
            audience: 'https://api.example.com'
        }
    }

    beforeEach( async () => {
        jest.clearAllMocks()
        
        app = express()
        middleware = await McpAuthMiddleware.create( {
            routes: testConfig,
            silent: true
        } )
        
        app.use( middleware.router() )
    } )

    describe( 'Basic Middleware Setup', () => {
        
        test( 'provides functional Express middleware', () => {
            const router = middleware.router()
            expect( typeof router ).toBe( 'function' )
        } )

        test( 'middleware can be used with Express app', () => {
            const testApp = express()
            
            expect( () => {
                testApp.use( middleware.router() )
            } ).not.toThrow()
        } )

    } )

    describe( 'Route Registration', () => {
        
        test( 'registers OAuth endpoints for configured routes', async () => {
            const response = await request( app )
                .get( '/api/auth/login' )
                .expect( 400 ) // HTTPS requirement should trigger first

            expect( response.body.error ).toBe( 'invalid_request' )
        } )

        test( 'handles non-existent routes appropriately', async () => {
            const response = await request( app )
                .get( '/nonexistent/auth/login' )
                .expect( 404 )
        } )

    } )

    describe( 'HTTPS Security Enforcement', () => {
        
        test( 'rejects non-HTTPS requests with proper error', async () => {
            const response = await request( app )
                .get( '/api/auth/login' )

            expect( response.status ).toBe( 400 )
            expect( response.body ).toMatchObject( {
                error: 'invalid_request',
                error_description: expect.stringContaining( 'OAuth 2.1 requires HTTPS' )
            } )
        } )

        test( 'accepts HTTPS requests', async () => {
            const httpsApp = express()
            httpsApp.use( ( req, res, next ) => {
                req.protocol = 'https'
                req.secure = true
                next()
            } )
            httpsApp.use( middleware.router() )

            const response = await request( httpsApp )
                .get( '/api/auth/login' )
                // Should not get HTTPS error (may get other auth errors)
            
            expect( response.status ).not.toBe( 400 )
        } )

    } )

    describe( 'Error Handling', () => {
        
        test( 'handles malformed requests gracefully', async () => {
            const response = await request( app )
                .post( '/api/auth/callback' )
                .send( 'malformed-data' )
                .expect( 400 )

            expect( response.body.error ).toBeDefined()
        } )

        test( 'returns proper JSON error responses', async () => {
            const response = await request( app )
                .get( '/api/auth/login' )
                .expect( 400 )
                .expect( 'Content-Type', /json/ )

            expect( response.body ).toHaveProperty( 'error' )
            expect( response.body ).toHaveProperty( 'error_description' )
        } )

    } )

} )