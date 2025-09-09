import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-client'

import { Logger } from '../../helpers/Logger.mjs'


class OAuth21Auth0TokenValidator {
    #config
    #jwksClient
    #validationCache
    #silent


    constructor( { config, silent = false } ) {
        this.#config = config
        this.#silent = silent
        this.#validationCache = new Map()
        
        this.#initializeJwksClient()
    }


    static createForAuth0( { config, silent = false } ) {
        return new OAuth21Auth0TokenValidator( { config, silent } )
    }


    async validate( { token } ) {
        return new Promise( ( resolve ) => {
            this.#validateToken( { token, resolve } )
        } )
    }


    async validateWithAudienceBinding( { token, audience } ) {
        const validationResult = await this.validate( { token } )
        
        if( !validationResult.isValid ) {
            return validationResult
        }

        const { decoded } = validationResult
        const audienceBinding = this.#validateAudienceBinding( { decoded, audience } )
        
        return {
            ...validationResult,
            audienceBinding
        }
    }


    async validateScopes( { token, requiredScopes } ) {
        return new Promise( async ( resolve ) => {
            const validationResult = await this.validate( { token } )
            
            if( !validationResult.isValid ) {
                resolve( {
                    hasRequiredScopes: false,
                    missingScopes: requiredScopes,
                    validationResult
                } )
                return
            }

            const { decoded } = validationResult
            const tokenScopes = this.#extractScopesFromToken( { decoded } )
            const missingScopes = requiredScopes
                .filter( ( scope ) => !tokenScopes.includes( scope ) )

            const hasRequiredScopes = missingScopes.length === 0

            resolve( {
                hasRequiredScopes,
                missingScopes,
                availableScopes: tokenScopes,
                validationResult
            } )
        } )
    }


    #initializeJwksClient() {
        const jwksUri = `${this.#config.providerUrl}/.well-known/jwks.json`
        
        this.#jwksClient = jwksClient( {
            jwksUri,
            timeout: 30000
        } )

        if( !this.#silent ) {
            Logger.info( { 
                silent: this.#silent, 
                message: `OAuth21Auth0TokenValidator initialized with JWKS URI: ${jwksUri}` 
            } )
        }
    }


    #validateToken( { token, resolve } ) {
        const cacheKey = `oauth21_auth0-${token.substring( 0, 20 )}`
        
        if( this.#validationCache.has( cacheKey ) ) {
            const cached = this.#validationCache.get( cacheKey )
            
            if( Date.now() - cached.timestamp < 120000 ) { // 2 minutes cache
                resolve( cached.result )
                return
            }
        }

        jwt.verify( 
            token, 
            ( header, callback ) => this.#getSigningKey( { header, callback } ), 
            {
                issuer: `${this.#config.providerUrl}/`,
                audience: this.#config.audience || this.#config.clientId,
                algorithms: [ 'RS256' ]
            },
            ( err, decoded ) => {
                const result = this.#processValidationResult( { err, decoded, token } )
                
                if( result.isValid ) {
                    this.#validationCache.set( cacheKey, {
                        result,
                        timestamp: Date.now()
                    } )
                }
                
                resolve( result )
            }
        )
    }


    #processValidationResult( { err, decoded, token } ) {
        if( err ) {
            Logger.error( { 
                silent: this.#silent, 
                message: `OAuth21Auth0 token validation failed: ${err.message}` 
            } )
            
            return {
                isValid: false,
                error: err.message,
                decoded: null,
                authType: 'oauth21_auth0'
            }
        } else {
            Logger.info( { 
                silent: this.#silent, 
                message: 'OAuth21Auth0 token validation successful' 
            } )
            
            return {
                isValid: true,
                error: null,
                decoded,
                authType: 'oauth21_auth0'
            }
        }
    }


    #validateAudienceBinding( { decoded, audience } ) {
        if( !audience ) {
            return { 
                isValidAudience: true, 
                message: 'No audience specified - skipping audience validation' 
            }
        }

        const tokenAudience = Array.isArray( decoded.aud ) ? decoded.aud : [ decoded.aud ]
        const isValidAudience = tokenAudience.includes( audience )

        return {
            isValidAudience,
            tokenAudience,
            requiredAudience: audience,
            message: isValidAudience 
                ? 'OAuth21Auth0 audience binding validation successful' 
                : `OAuth21Auth0 audience mismatch: token aud=${tokenAudience.join(', ')}, required=${audience}`
        }
    }


    #extractScopesFromToken( { decoded } ) {
        if( decoded.scope ) {
            return decoded.scope.split( ' ' )
        }
        
        if( decoded.scp && Array.isArray( decoded.scp ) ) {
            return decoded.scp
        }
        
        return []
    }


    #getSigningKey( { header, callback } ) {
        this.#jwksClient.getSigningKey( header.kid, ( err, key ) => {
            if( err ) {
                callback( err )
            } else {
                const signingKey = key.publicKey || key.rsaPublicKey
                callback( null, signingKey )
            }
        } )
    }


    clearValidationCache() {
        this.#validationCache.clear()
    }


    getAuthType() {
        return 'oauth21_auth0'
    }


    getConfig() {
        return { ...this.#config }
    }
}

export { OAuth21Auth0TokenValidator }