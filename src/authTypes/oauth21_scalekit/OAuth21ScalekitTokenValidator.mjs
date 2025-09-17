import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-client'

import { Logger } from '../../helpers/Logger.mjs'


class OAuth21ScalekitTokenValidator {
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


    static createForScalekit( { config, silent = false } ) {
        return new OAuth21ScalekitTokenValidator( { config, silent } )
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


    async validateMcpScopes( { token, mcpCapability } ) {
        // MCP-specific scope validation
        // Example: mcp:tools:*, mcp:resources:read
        const validationResult = await this.validate( { token } )

        if( !validationResult.isValid ) {
            return {
                isValid: false,
                hasCapability: false,
                error: validationResult.error
            }
        }

        const { decoded } = validationResult
        const tokenScopes = this.#extractScopesFromToken( { decoded } )

        // Check for MCP capability
        const hasCapability = tokenScopes.some( ( scope ) => {
            // Exact match
            if( scope === mcpCapability ) return true

            // Wildcard match (e.g., mcp:tools:* matches mcp:tools:read)
            const scopeParts = scope.split( ':' )
            const capabilityParts = mcpCapability.split( ':' )

            if( scopeParts.length >= 2 && scopeParts[scopeParts.length - 1] === '*' ) {
                const scopePrefix = scopeParts.slice( 0, -1 ).join( ':' )
                const capabilityPrefix = capabilityParts.slice( 0, scopeParts.length - 1 ).join( ':' )
                return scopePrefix === capabilityPrefix
            }

            return false
        } )

        return {
            isValid: true,
            hasCapability,
            availableScopes: tokenScopes,
            decoded
        }
    }


    #initializeJwksClient() {
        const jwksUrl = this.#config.jwksUrl

        this.#jwksClient = jwksClient( {
            jwksUri: jwksUrl,
            timeout: 30000
        } )

        Logger.info( {
            silent: this.#silent,
            message: `Initialized JWKS client for ScaleKit: ${jwksUrl}`
        } )
    }


    async #validateToken( { token, resolve } ) {
        try {
            // Check cache first
            const cached = this.#validationCache.get( token )
            if( cached && cached.expiresAt > Date.now() ) {
                resolve( cached.result )
                return
            }

            // Decode token header to get kid
            const decoded = jwt.decode( token, { complete: true } )

            if( !decoded ) {
                resolve( {
                    isValid: false,
                    error: 'Invalid token format',
                    decoded: null
                } )
                return
            }

            const { kid } = decoded.header

            // Get signing key from JWKS using Promise-based approach for jwks-client 2.x
            const key = await new Promise( ( keyResolve, keyReject ) => {
                this.#jwksClient.getSigningKey( kid, ( err, result ) => {
                    if( err ) {
                        keyReject( err )
                    } else {
                        keyResolve( result )
                    }
                } )
            } )

            // For jwks-client 2.x, the key structure is different
            const signingKey = key.publicKey || key.rsaPublicKey || key.getPublicKey()

            // Verify token using Promise-based approach
            const verifiedDecoded = await new Promise( ( verifyResolve, verifyReject ) => {
                jwt.verify(
                    token,
                    signingKey,
                    {
                        algorithms: [ 'RS256' ],
                        issuer: this.#config.providerUrl,  // Correct ScaleKit issuer (base URL)
                        audience: this.#config.resource
                    },
                    ( verifyErr, decoded ) => {
                        if( verifyErr ) {
                            verifyReject( verifyErr )
                        } else {
                            verifyResolve( decoded )
                        }
                    }
                )
            } )

            const result = {
                isValid: true,
                decoded: verifiedDecoded,
                error: null
            }

            // Cache the result
            this.#validationCache.set( token, {
                result,
                expiresAt: Date.now() + 300000  // 5 minutes
            } )

            resolve( result )

        } catch( error ) {
            resolve( {
                isValid: false,
                error: error.message || 'Failed to get signing key',
                decoded: null
            } )
        }
    }


    #validateAudienceBinding( { decoded, audience } ) {
        const tokenAudience = decoded.aud

        if( Array.isArray( tokenAudience ) ) {
            return {
                isValid: tokenAudience.includes( audience ),
                tokenAudience,
                expectedAudience: audience
            }
        }

        return {
            isValid: tokenAudience === audience,
            tokenAudience,
            expectedAudience: audience
        }
    }


    #extractScopesFromToken( { decoded } ) {
        const scope = decoded.scope || decoded.scopes || ''

        if( Array.isArray( scope ) ) {
            return scope
        }

        if( typeof scope === 'string' ) {
            return scope.split( ' ' ).filter( s => s.length > 0 )
        }

        return []
    }


    clearCache() {
        this.#validationCache.clear()
        Logger.info( {
            silent: this.#silent,
            message: 'Token validation cache cleared'
        } )
    }


    getCacheSize() {
        return this.#validationCache.size
    }


    static isScalekitToken( { token } ) {
        try {
            const decoded = jwt.decode( token, { complete: true } )
            if( !decoded ) return false

            // With custom domain support, we accept any valid HTTPS issuer
            // excluding auth0.com to avoid confusion with Auth0 tokens
            const issuer = decoded.payload.iss
            return issuer && issuer.startsWith( 'https://' ) && !issuer.includes( 'auth0.com' )
        } catch {
            return false
        }
    }
}

export { OAuth21ScalekitTokenValidator }