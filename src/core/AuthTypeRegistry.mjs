import { Logger } from '../helpers/Logger.mjs'


class AuthTypeRegistry {
    #authTypes
    #silent


    constructor( { silent = false } ) {
        this.#silent = silent
        this.#authTypes = new Map()
        
        this.#initializeAuthTypes()
    }


    static getSupportedAuthTypes() {
        const registry = new AuthTypeRegistry( { silent: true } )
        const authTypes = [ ...registry.#authTypes.keys() ]

        return { authTypes }
    }


    static getHandler( { authType } ) {
        const registry = new AuthTypeRegistry( { silent: true } )
        const handler = registry.#authTypes.get( authType )

        if( !handler ) {
            const supportedTypes = [ ...registry.#authTypes.keys() ]
            throw new Error( `Unknown authType "${authType}". Supported types: ${supportedTypes.join( ', ' )}` )
        }

        return { handler }
    }


    static isSupported( { authType } ) {
        const registry = new AuthTypeRegistry( { silent: true } )
        const isSupported = registry.#authTypes.has( authType )

        return { isSupported }
    }


    #initializeAuthTypes() {
        this.#authTypes.set( 'oauth21_auth0', {
            name: 'OAuth 2.1 with Auth0',
            description: 'OAuth 2.1 implementation for Auth0 provider',
            schemaPath: '../authTypes/oauth21_auth0/OAuth21Auth0Schema.mjs',
            providerPath: '../authTypes/oauth21_auth0/OAuth21Auth0Provider.mjs',
            tokenValidatorPath: '../authTypes/oauth21_auth0/OAuth21Auth0TokenValidator.mjs',
            flowHandlerPath: '../authTypes/oauth21_auth0/OAuth21Auth0FlowHandler.mjs',
            supportedFlows: [ 'authorization_code', 'client_credentials', 'refresh_token' ],
            defaultScopes: 'openid profile email',
            requiredFields: [ 'providerUrl', 'clientId', 'clientSecret', 'scope', 'audience' ],
            optionalFields: [ 'redirectUri', 'responseType', 'grantType', 'tokenEndpoint', 'userInfoEndpoint' ]
        } )

        this.#authTypes.set( 'staticBearer', {
            name: 'Static Bearer Token',
            description: 'Simple static bearer token authentication',
            schemaPath: '../authTypes/staticBearer/StaticBearerSchema.mjs',
            providerPath: '../authTypes/staticBearer/StaticBearerProvider.mjs',
            tokenValidatorPath: '../authTypes/staticBearer/StaticBearerTokenValidator.mjs',
            flowHandlerPath: null,
            supportedFlows: [],
            defaultScopes: '',
            requiredFields: [ 'token' ],
            optionalFields: []
        } )

        Logger.info( { 
            silent: this.#silent, 
            message: `AuthTypeRegistry initialized with ${this.#authTypes.size} auth types` 
        } )
    }
}

export { AuthTypeRegistry }