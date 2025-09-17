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
        this.#authTypes.set( 'oauth21_scalekit', {
            name: 'OAuth 2.1 with ScaleKit',
            description: 'OAuth 2.1 implementation for ScaleKit MCP servers',
            schemaPath: '../authTypes/oauth21_scalekit/OAuth21ScalekitSchema.mjs',
            providerPath: '../authTypes/oauth21_scalekit/OAuth21ScalekitProvider.mjs',
            tokenValidatorPath: '../authTypes/oauth21_scalekit/OAuth21ScalekitTokenValidator.mjs',
            flowHandlerPath: '../authTypes/oauth21_scalekit/OAuth21ScalekitFlowHandler.mjs',
            supportedFlows: [ 'authorization_code', 'client_credentials', 'refresh_token' ],
            defaultScopes: 'mcp:tools:* mcp:resources:read mcp:resources:write',
            requiredFields: [ 'providerUrl', 'mcpId', 'clientId', 'clientSecret', 'resource', 'scope' ],
            optionalFields: [ 'resourceDocumentation', 'routePath', 'redirectUri', 'responseType', 'grantType', 'tokenEndpoint', 'userInfoEndpoint' ]
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