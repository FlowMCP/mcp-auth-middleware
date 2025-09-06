import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-client'


class TokenValidator {
    #config
    #jwksClient
    #silent


    constructor( { silent = false } ) {
        this.#silent = silent
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

        const jwksClientInstance = jwksClient( {
            jwksUri: config.jwksUri,
            timeout: 30000
        } )
        
        validator.#config = config
        validator.#jwksClient = jwksClientInstance

        return validator
    }


    validate( { token } ) {
        return new Promise( ( resolve ) => {
            this.#validateToken( { token, resolve } )
        } )
    }


    #validateToken( { token, resolve } ) {
        jwt.verify( 
            token, 
            this.#getKey.bind( this ), 
            {
                issuer: this.#config.issuer,
                audience: this.#config.clientId,
                algorithms: [ 'RS256' ]
            },
            ( err, decoded ) => {
                if( err ) {
                    if( !this.#silent ) {
                        console.log( `Token validation failed: ${err.message}` )
                    }
                    
                    resolve( {
                        isValid: false,
                        error: err.message,
                        decoded: null
                    } )
                } else {
                    if( !this.#silent ) {
                        console.log( 'Token validation successful' )
                    }
                    
                    resolve( {
                        isValid: true,
                        error: null,
                        decoded
                    } )
                }
            }
        )
    }


    #getKey( header, callback ) {
        this.#jwksClient.getSigningKey( header.kid, ( err, key ) => {
            if( err ) {
                callback( err )
            } else {
                const signingKey = key.publicKey || key.rsaPublicKey
                callback( null, signingKey )
            }
        } )
    }


    validateScopes( { token, requiredScopes } ) {
        const { isValid, decoded } = this.validate( { token } )
        
        if( !isValid ) {
            return { hasRequiredScopes: false, missingScopes: requiredScopes }
        }

        const tokenScopes = decoded.scope ? decoded.scope.split( ' ' ) : []
        const missingScopes = requiredScopes
            .filter( ( scope ) => !tokenScopes.includes( scope ) )

        const hasRequiredScopes = missingScopes.length === 0

        return { 
            hasRequiredScopes,
            missingScopes,
            availableScopes: tokenScopes
        }
    }
}

export { TokenValidator }