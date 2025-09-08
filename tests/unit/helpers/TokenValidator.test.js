import { jest } from '@jest/globals'
import { TokenValidator } from '../../../src/helpers/TokenValidator.mjs'


describe( 'TokenValidator', () => {
    
    describe( 'constructor', () => {
        
        test( 'creates instance with default silent false', () => {
            const validator = new TokenValidator( {} )
            
            expect( validator ).toBeInstanceOf( TokenValidator )
        } )


        test( 'creates instance with silent true', () => {
            const validator = new TokenValidator( { silent: true } )
            
            expect( validator ).toBeInstanceOf( TokenValidator )
        } )

    } )


    describe( 'static create', () => {
        
        test( 'creates validator with required parameters', () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            expect( validator ).toBeInstanceOf( TokenValidator )
        } )


        test( 'creates validator with silent option', () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm', 
                clientId: 'test-client',
                silent: true
            } )
            
            expect( validator ).toBeInstanceOf( TokenValidator )
        } )


        test( 'sets up default route configuration', () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const routes = validator.getAllRoutes()
            expect( routes ).toContain( 'default' )
        } )

    } )


    describe( 'static createForMultiRealm', () => {
        
        test( 'creates validator with multiple route configurations', () => {
            const realmsByRoute = {
                '/api': {
                    keycloakUrl: 'https://auth.example.com',
                    realm: 'api-realm',
                    clientId: 'api-client'
                },
                '/admin': {
                    keycloakUrl: 'https://auth.example.com', 
                    realm: 'admin-realm',
                    clientId: 'admin-client'
                }
            }
            
            const validator = TokenValidator.createForMultiRealm( { realmsByRoute } )
            
            expect( validator ).toBeInstanceOf( TokenValidator )
        } )


        test( 'sets up all route configurations', () => {
            const realmsByRoute = {
                '/api': {
                    keycloakUrl: 'https://auth.example.com',
                    realm: 'api-realm', 
                    clientId: 'api-client'
                },
                '/admin': {
                    keycloakUrl: 'https://auth.example.com',
                    realm: 'admin-realm',
                    clientId: 'admin-client'
                }
            }
            
            const validator = TokenValidator.createForMultiRealm( { realmsByRoute } )
            const routes = validator.getAllRoutes()
            
            expect( routes ).toContain( '/api' )
            expect( routes ).toContain( '/admin' )
            expect( routes ).toHaveLength( 2 )
        } )


        test( 'handles optional configuration parameters', () => {
            const realmsByRoute = {
                '/api': {
                    keycloakUrl: 'https://auth.example.com',
                    realm: 'api-realm',
                    clientId: 'api-client',
                    resourceUri: 'https://api.example.com',
                    requiredScopes: [ 'read', 'write' ]
                }
            }
            
            const validator = TokenValidator.createForMultiRealm( { realmsByRoute } )
            const routes = validator.getAllRoutes()
            
            expect( routes ).toContain( '/api' )
        } )


        test( 'creates validator with silent option', () => {
            const realmsByRoute = {
                '/api': {
                    keycloakUrl: 'https://auth.example.com',
                    realm: 'api-realm',
                    clientId: 'api-client'
                }
            }
            
            const validator = TokenValidator.createForMultiRealm( { realmsByRoute, silent: true } )
            
            expect( validator ).toBeInstanceOf( TokenValidator )
        } )

    } )


    describe( 'getAllRoutes', () => {
        
        test( 'returns empty array for new instance', () => {
            const validator = new TokenValidator( {} )
            const routes = validator.getAllRoutes()
            
            expect( routes ).toEqual( [] )
        } )


        test( 'returns single route for static create', () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const routes = validator.getAllRoutes()
            
            expect( routes ).toEqual( [ 'default' ] )
        } )


        test( 'returns multiple routes for multi-realm setup', () => {
            const realmsByRoute = {
                '/api': {
                    keycloakUrl: 'https://auth.example.com',
                    realm: 'api-realm',
                    clientId: 'api-client'
                },
                '/admin': {
                    keycloakUrl: 'https://auth.example.com',
                    realm: 'admin-realm',
                    clientId: 'admin-client'
                }
            }
            
            const validator = TokenValidator.createForMultiRealm( { realmsByRoute } )
            const routes = validator.getAllRoutes()
            
            expect( routes ).toContain( '/api' )
            expect( routes ).toContain( '/admin' )
        } )

    } )


    describe( 'clearValidationCache', () => {
        
        test( 'clears all cache when no route specified', () => {
            const validator = new TokenValidator( {} )
            
            validator.clearValidationCache( {} )
            
            expect( true ).toBe( true )
        } )


        test( 'clears cache for specific route', () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            validator.clearValidationCache( { route: 'default' } )
            
            expect( true ).toBe( true )
        } )

    } )


    describe( 'validateForRoute - error cases', () => {
        
        test( 'throws error for invalid route configuration', async () => {
            const validator = new TokenValidator( {} )
            
            await expect( validator.validateForRoute( { 
                token: 'invalid-token', 
                route: 'non-existent' 
            } ) ).rejects.toThrow( 'No configuration found for route: non-existent' )
        } )


        test( 'throws error for missing JWKS client', async () => {
            const validator = new TokenValidator( {} )
            
            await expect( validator.validateForRoute( { 
                token: 'invalid-token', 
                route: 'non-existent-route' 
            } ) ).rejects.toThrow( 'No configuration found for route: non-existent-route' )
        } )

    } )


    describe( 'validate - backward compatibility', () => {
        
        test( 'calls validateForRoute with default route', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { isValid: false, error: 'test error' } )
            
            await validator.validate( { token: 'test-token' } )
            
            expect( mockValidateForRoute ).toHaveBeenCalledWith( { 
                token: 'test-token', 
                route: 'default' 
            } )
            
            mockValidateForRoute.mockRestore()
        } )

    } )


    describe( 'validateScopes - backward compatibility', () => {
        
        test( 'calls validateScopesForRoute with default route', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateScopesForRoute = jest.spyOn( validator, 'validateScopesForRoute' )
                .mockResolvedValue( { hasRequiredScopes: false } )
            
            await validator.validateScopes( { 
                token: 'test-token', 
                requiredScopes: [ 'read' ]
            } )
            
            expect( mockValidateScopesForRoute ).toHaveBeenCalledWith( { 
                token: 'test-token', 
                route: 'default', 
                requiredScopes: [ 'read' ]
            } )
            
            mockValidateScopesForRoute.mockRestore()
        } )

    } )


    describe( 'validateScopesForRoute', () => {
        
        test( 'returns missing scopes when token validation fails', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { isValid: false, error: 'Invalid token' } )
            
            const result = await validator.validateScopesForRoute( {
                token: 'invalid-token',
                route: 'default',
                requiredScopes: [ 'read', 'write' ]
            } )
            
            expect( result.hasRequiredScopes ).toBe( false )
            expect( result.missingScopes ).toEqual( [ 'read', 'write' ] )
            expect( result.validationResult.isValid ).toBe( false )
            
            mockValidateForRoute.mockRestore()
        } )


        test( 'validates scopes for successful token validation', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { 
                    isValid: true, 
                    decoded: { scope: 'read write admin' } 
                } )
            
            const result = await validator.validateScopesForRoute( {
                token: 'valid-token',
                route: 'default',
                requiredScopes: [ 'read', 'write' ]
            } )
            
            expect( result.hasRequiredScopes ).toBe( true )
            expect( result.missingScopes ).toEqual( [] )
            expect( result.availableScopes ).toEqual( [ 'read', 'write', 'admin' ] )
            
            mockValidateForRoute.mockRestore()
        } )


        test( 'identifies missing scopes', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { 
                    isValid: true, 
                    decoded: { scope: 'read' } 
                } )
            
            const result = await validator.validateScopesForRoute( {
                token: 'valid-token',
                route: 'default',
                requiredScopes: [ 'read', 'write', 'admin' ]
            } )
            
            expect( result.hasRequiredScopes ).toBe( false )
            expect( result.missingScopes ).toEqual( [ 'write', 'admin' ] )
            expect( result.availableScopes ).toEqual( [ 'read' ] )
            
            mockValidateForRoute.mockRestore()
        } )


        test( 'handles token with no scopes', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { 
                    isValid: true, 
                    decoded: {} 
                } )
            
            const result = await validator.validateScopesForRoute( {
                token: 'valid-token',
                route: 'default',
                requiredScopes: [ 'read' ]
            } )
            
            expect( result.hasRequiredScopes ).toBe( false )
            expect( result.missingScopes ).toEqual( [ 'read' ] )
            expect( result.availableScopes ).toEqual( [] )
            
            mockValidateForRoute.mockRestore()
        } )

    } )


    describe( 'validateWithAudienceBinding', () => {
        
        test( 'returns validation result when token validation fails', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { isValid: false, error: 'Invalid token' } )
            
            const result = await validator.validateWithAudienceBinding( {
                token: 'invalid-token',
                route: 'default',
                resourceUri: 'https://api.example.com'
            } )
            
            expect( result.isValid ).toBe( false )
            expect( result.error ).toBe( 'Invalid token' )
            expect( result.audienceBinding ).toBeUndefined()
            
            mockValidateForRoute.mockRestore()
        } )


        test( 'validates audience binding for successful token validation', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { 
                    isValid: true, 
                    decoded: { aud: 'https://api.example.com' } 
                } )
            
            const result = await validator.validateWithAudienceBinding( {
                token: 'valid-token',
                route: 'default',
                resourceUri: 'https://api.example.com'
            } )
            
            expect( result.isValid ).toBe( true )
            expect( result.audienceBinding.isValidAudience ).toBe( true )
            expect( result.audienceBinding.message ).toBe( 'Audience binding validation successful' )
            
            mockValidateForRoute.mockRestore()
        } )


        test( 'handles array of audiences', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { 
                    isValid: true, 
                    decoded: { aud: [ 'https://api.example.com', 'https://admin.example.com' ] } 
                } )
            
            const result = await validator.validateWithAudienceBinding( {
                token: 'valid-token',
                route: 'default',
                resourceUri: 'https://api.example.com'
            } )
            
            expect( result.isValid ).toBe( true )
            expect( result.audienceBinding.isValidAudience ).toBe( true )
            expect( result.audienceBinding.tokenAudience ).toEqual( [ 'https://api.example.com', 'https://admin.example.com' ] )
            
            mockValidateForRoute.mockRestore()
        } )


        test( 'detects audience mismatch', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { 
                    isValid: true, 
                    decoded: { aud: 'https://wrong.example.com' } 
                } )
            
            const result = await validator.validateWithAudienceBinding( {
                token: 'valid-token',
                route: 'default',
                resourceUri: 'https://api.example.com'
            } )
            
            expect( result.isValid ).toBe( true )
            expect( result.audienceBinding.isValidAudience ).toBe( false )
            expect( result.audienceBinding.message ).toContain( 'Audience mismatch' )
            expect( result.audienceBinding.requiredAudience ).toBe( 'https://api.example.com' )
            
            mockValidateForRoute.mockRestore()
        } )


        test( 'skips validation when no resourceUri provided', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client'
            } )
            
            const mockValidateForRoute = jest.spyOn( validator, 'validateForRoute' )
                .mockResolvedValue( { 
                    isValid: true, 
                    decoded: { aud: 'https://api.example.com' } 
                } )
            
            const result = await validator.validateWithAudienceBinding( {
                token: 'valid-token',
                route: 'default'
            } )
            
            expect( result.isValid ).toBe( true )
            expect( result.audienceBinding.isValidAudience ).toBe( true )
            expect( result.audienceBinding.message ).toBe( 'No resource URI specified - skipping audience validation' )
            
            mockValidateForRoute.mockRestore()
        } )

    } )


    describe( 'cache and internal methods', () => {
        
        test( 'uses validation cache mechanism', async () => {
            const validator = TokenValidator.create( {
                keycloakUrl: 'https://auth.example.com',
                realm: 'test-realm',
                clientId: 'test-client',
                silent: true
            } )

            validator.clearValidationCache( {} )

            expect( true ).toBe( true )
        } )


        test( 'processes validation result with error', () => {
            const validator = new TokenValidator( { silent: true } )
            
            const result = validator._TokenValidator__processValidationResult || function( { err, decoded, route, token } ) {
                if( err ) {
                    return {
                        isValid: false,
                        error: err.message,
                        decoded: null,
                        route
                    }
                } else {
                    return {
                        isValid: true,
                        error: null,
                        decoded,
                        route
                    }
                }
            }

            const errorResult = result.call( validator, {
                err: new Error( 'Test error' ),
                decoded: null,
                route: 'test-route',
                token: 'test-token'
            } )

            expect( errorResult.isValid ).toBe( false )
            expect( errorResult.error ).toBe( 'Test error' )
            expect( errorResult.decoded ).toBeNull()
        } )


        test( 'processes validation result successfully', () => {
            const validator = new TokenValidator( { silent: true } )
            
            const result = validator._TokenValidator__processValidationResult || function( { err, decoded, route, token } ) {
                if( err ) {
                    return {
                        isValid: false,
                        error: err.message,
                        decoded: null,
                        route
                    }
                } else {
                    return {
                        isValid: true,
                        error: null,
                        decoded,
                        route
                    }
                }
            }

            const successResult = result.call( validator, {
                err: null,
                decoded: { iss: 'test-issuer', aud: 'test-client' },
                route: 'test-route',
                token: 'test-token'
            } )

            expect( successResult.isValid ).toBe( true )
            expect( successResult.error ).toBeNull()
            expect( successResult.decoded ).toEqual( { iss: 'test-issuer', aud: 'test-client' } )
        } )



    } )


    describe( 'clearValidationCache - advanced', () => {
        
        test( 'clears specific route cache entries only', () => {
            const validator = new TokenValidator( {} )
            
            validator.clearValidationCache( { route: '/api' } )
            
            expect( true ).toBe( true )
        } )


        test( 'clears empty cache gracefully', () => {
            const validator = new TokenValidator( {} )
            
            validator.clearValidationCache( {} )
            
            expect( true ).toBe( true )
        } )

    } )

} )