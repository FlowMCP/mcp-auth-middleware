import { Logger } from '../../helpers/Logger.mjs'


class OAuth21Auth0Provider {
    #config
    #silent

    constructor( { config, silent = false } ) {
        this.#config = config
        this.#silent = silent
    }


    detectProviderType( { providerUrl } ) {
        return !!(providerUrl && providerUrl.includes( 'auth0.com' ))
    }


    normalizeConfiguration( { config } ) {
        const { providerUrl, realm, clientId, clientSecret, scope, audience, resourceUri } = config
        
        const normalizedConfig = {
            providerUrl,
            realm: realm || 'oauth21-auth0',
            clientId,
            clientSecret,
            scope: scope || 'openid profile email',
            audience,
            resourceUri,
            authFlow: 'authorization_code',
            authType: 'oauth21_auth0'
        }

        return { normalizedConfig }
    }


    generateEndpoints( { config } ) {
        const { providerUrl } = config
        
        const endpoints = {
            authorizationEndpoint: `${providerUrl}/authorize`,
            tokenEndpoint: config.tokenEndpoint || `${providerUrl}/oauth/token`,
            deviceAuthorizationEndpoint: `${providerUrl}/oauth/device/code`,
            jwksUrl: `${providerUrl}/.well-known/jwks.json`,
            userInfoUrl: config.userInfoEndpoint || `${providerUrl}/userinfo`,
            introspectionUrl: `${providerUrl}/oauth/token/introspection`,
            discoveryUrl: `${providerUrl}/.well-known/openid_configuration`
        }

        return { endpoints }
    }


    static validateOAuth21Auth0Config( { config } ) {
        const struct = { status: false, messages: [] }

        if( !config || typeof config !== 'object' ) {
            struct['messages'].push( 'OAuth21Auth0 config must be a valid object' )
            return struct
        }

        const requiredFields = [ 'providerUrl', 'clientId', 'clientSecret', 'scope', 'audience' ]
        const missing = requiredFields.filter( field => !config[field] )
        
        if( missing.length > 0 ) {
            struct['messages'].push( `OAuth21Auth0 config missing required fields: ${missing.join( ', ' )}` )
        }

        if( config.providerUrl && !config.providerUrl.includes( 'auth0.com' ) ) {
            struct['messages'].push( 'OAuth21Auth0 provider requires auth0.com domain in providerUrl' )
        }

        if( config.scope && typeof config.scope !== 'string' ) {
            struct['messages'].push( 'OAuth21Auth0 scope must be a string' )
        }

        if( config.audience && typeof config.audience !== 'string' ) {
            struct['messages'].push( 'OAuth21Auth0 audience must be a string' )
        }

        struct['status'] = struct['messages'].length === 0
        return struct
    }


    getProviderName() {
        return 'oauth21_auth0'
    }


    getDisplayName() {
        return 'OAuth 2.1 with Auth0'
    }


    static getSupportedFlows() {
        return [ 'authorization_code', 'client_credentials', 'refresh_token' ]
    }


    static getDefaultScopes() {
        return 'openid profile email'
    }


    static getAuthType() {
        return 'oauth21_auth0'
    }
}

export { OAuth21Auth0Provider }