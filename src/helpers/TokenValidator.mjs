import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-client'

import { Logger } from './Logger.mjs'


class TokenValidator {
    #routeConfigs
    #jwksClients
    #validationCache
    #silent


    constructor( { silent = false } ) {
        this.#silent = silent
        this.#routeConfigs = new Map()
        this.#jwksClients = new Map()
        this.#validationCache = new Map()
    }


    static createForMultiRealm( { routes, silent = false } ) {
        const validator = new TokenValidator( { silent } )
        
        // Initialize all route configurations and JWKS clients
        Object.entries( routes ).forEach( ( [ route, config ] ) => {
            const normalizedConfig = {
                keycloakUrl: config.keycloakUrl,
                realm: config.realm,
                clientId: config.clientId,
                jwksUri: `${config.keycloakUrl}/realms/${config.realm}/protocol/openid-connect/certs`,
                issuer: `${config.keycloakUrl}/realms/${config.realm}`,
                resourceUri: config.resourceUri || '',
                requiredScopes: config.requiredScopes || []
            }
            
            validator.#routeConfigs.set( route, normalizedConfig )
            
            // Create JWKS client for this route
            const jwksClientInstance = jwksClient( {
                jwksUri: normalizedConfig.jwksUri,
                timeout: 30000
            } )
            
            validator.#jwksClients.set( route, jwksClientInstance )
        } )

        return validator
    }


    static create( { keycloakUrl, realm, clientId, silent = false } ) {
        const validator = new TokenValidator( { silent } )
        
        const config = {
            keycloakUrl,
            realm,
            clientId,
            jwksUri: `${keycloakUrl}/realms/${realm}/protocol/openid-connect/certs`,
            issuer: `${keycloakUrl}/realms/${realm}`
        }

        validator.#routeConfigs.set( 'default', config )

        const jwksClientInstance = jwksClient( {
            jwksUri: config.jwksUri,
            timeout: 30000
        } )
        
        validator.#jwksClients.set( 'default', jwksClientInstance )

        return validator
    }


    validateForRoute( { token, route } ) {
        return new Promise( ( resolve ) => {
            this.#validateTokenForRoute( { token, route, resolve } )
        } )
    }


    async validateWithAudienceBinding( { token, route, resourceUri } ) {
        const validationResult = await this.validateForRoute( { token, route } )
        
        if( !validationResult.isValid ) {
            return validationResult
        }

        // RFC 8707: Resource Indicators - Audience binding validation
        const { decoded } = validationResult
        const audienceBinding = this.#validateAudienceBinding( { decoded, resourceUri } )
        
        return {
            ...validationResult,
            audienceBinding
        }
    }


    validateScopesForRoute( { token, route, requiredScopes } ) {
        return new Promise( async ( resolve ) => {
            const validationResult = await this.validateForRoute( { token, route } )
            
            if( !validationResult.isValid ) {
                resolve( {
                    hasRequiredScopes: false,
                    missingScopes: requiredScopes,
                    validationResult
                } )
                return
            }

            const { decoded } = validationResult
            const tokenScopes = decoded.scope ? decoded.scope.split( ' ' ) : []
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


    // Backwards compatibility
    validate( { token } ) {
        return this.validateForRoute( { token, route: 'default' } )
    }


    validateScopes( { token, requiredScopes } ) {
        return this.validateScopesForRoute( { token, route: 'default', requiredScopes } )
    }


    #validateTokenForRoute( { token, route, resolve } ) {
        const config = this.#getConfigForRoute( { route } )
        const jwksClient = this.#getJwksClientForRoute( { route } )
        
        // Check cache first
        const cacheKey = `${route}-${token.substring( 0, 20 )}`
        if( this.#validationCache.has( cacheKey ) ) {
            const cached = this.#validationCache.get( cacheKey )
            
            // Check if cache is still fresh (2 minutes)
            if( Date.now() - cached.timestamp < 120000 ) {
                resolve( cached.result )
                return
            }
        }

        jwt.verify( 
            token, 
            ( header, callback ) => this.#getKeyForRoute( { header, callback, jwksClient } ), 
            {
                issuer: config.issuer,
                audience: config.clientId,
                algorithms: [ 'RS256' ]
            },
            ( err, decoded ) => {
                const result = this.#processValidationResult( { err, decoded, route, token } )
                
                // Cache successful validations
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


    #processValidationResult( { err, decoded, route, token } ) {
        if( err ) {
            Logger.error( { 
                silent: this.#silent, 
                message: `Token validation failed for route ${route}: ${err.message}` 
            } )
            
            return {
                isValid: false,
                error: err.message,
                decoded: null,
                route
            }
        } else {
            Logger.info( { 
                silent: this.#silent, 
                message: `Token validation successful for route ${route}` 
            } )
            
            return {
                isValid: true,
                error: null,
                decoded,
                route
            }
        }
    }


    #validateAudienceBinding( { decoded, resourceUri } ) {
        if( !resourceUri ) {
            return { isValidAudience: true, message: 'No resource URI specified - skipping audience validation' }
        }

        const tokenAudience = Array.isArray( decoded.aud ) ? decoded.aud : [ decoded.aud ]
        const isValidAudience = tokenAudience.includes( resourceUri )

        return {
            isValidAudience,
            tokenAudience,
            requiredAudience: resourceUri,
            message: isValidAudience 
                ? 'Audience binding validation successful' 
                : `Audience mismatch: token aud=${tokenAudience.join(', ')}, required=${resourceUri}`
        }
    }


    #getConfigForRoute( { route } ) {
        const config = this.#routeConfigs.get( route )
        
        if( !config ) {
            throw new Error( `No configuration found for route: ${route}` )
        }

        return config
    }


    #getJwksClientForRoute( { route } ) {
        const jwksClient = this.#jwksClients.get( route )
        
        if( !jwksClient ) {
            throw new Error( `No JWKS client found for route: ${route}` )
        }

        return jwksClient
    }


    #getKeyForRoute( { header, callback, jwksClient } ) {
        jwksClient.getSigningKey( header.kid, ( err, key ) => {
            if( err ) {
                callback( err )
            } else {
                const signingKey = key.publicKey || key.rsaPublicKey
                callback( null, signingKey )
            }
        } )
    }


    getAllRoutes() {
        return Array.from( this.#routeConfigs.keys() )
    }


    clearValidationCache( { route } ) {
        if( route ) {
            const keysToDelete = Array.from( this.#validationCache.keys() )
                .filter( ( key ) => key.startsWith( `${route}-` ) )
            
            keysToDelete.forEach( ( key ) => this.#validationCache.delete( key ) )
        } else {
            this.#validationCache.clear()
        }
    }
}

export { TokenValidator }