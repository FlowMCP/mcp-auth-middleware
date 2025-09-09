import { Logger } from '../../helpers/Logger.mjs'


class StaticBearerTokenValidator {
    #configuredToken
    #silent


    constructor( { config, silent = false } ) {
        this.#configuredToken = config.token.trim()
        this.#silent = silent
    }


    static createForStaticBearer( { config, silent = false } ) {
        return new StaticBearerTokenValidator( { config, silent } )
    }


    async validate( { token } ) {
        return new Promise( ( resolve ) => {
            this.#validateToken( { token, resolve } )
        } )
    }


    async validateScopes( { token, requiredScopes = [] } ) {
        return new Promise( async ( resolve ) => {
            resolve( {
                hasRequiredScopes: true,
                missingScopes: [],
                availableScopes: [],
                validationResult: await this.validate( { token } )
            } )
        } )
    }


    #validateToken( { token, resolve } ) {
        const cleanToken = token.replace( /^Bearer\s+/i, '' ).trim()
        const isValid = cleanToken === this.#configuredToken

        const result = {
            isValid,
            error: isValid ? null : 'Invalid bearer token',
            decoded: isValid ? { token: cleanToken, authType: 'staticBearer' } : null,
            authType: 'staticBearer'
        }

        Logger.info( { 
            silent: this.#silent, 
            message: `StaticBearer token validation ${isValid ? 'successful' : 'failed'}` 
        } )

        resolve( result )
    }


    clearValidationCache() {
        // No cache for static bearer tokens
    }


    getAuthType() {
        return 'staticBearer'
    }


    getConfig() {
        return { 
            authType: 'staticBearer',
            tokenLength: this.#configuredToken.length
        }
    }
}

export { StaticBearerTokenValidator }