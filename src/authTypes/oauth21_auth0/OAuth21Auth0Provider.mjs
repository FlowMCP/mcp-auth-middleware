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
        // Preserve all original config fields and only add/override provider-specific ones
        const normalizedConfig = {
            ...config,  // Keep all Entry-Point defaults and user config
            authFlow: 'authorization_code',  // Provider-specific constant
            authType: 'oauth21_auth0'        // Provider-specific constant
        }

        return { normalizedConfig }
    }


    generateEndpoints( { config } ) {
        const { providerUrl, tokenEndpoint, userInfoEndpoint } = config

        const endpoints = {
            // OAuth 2.1 endpoints (RFC naming convention)
            authorizationEndpoint: `${providerUrl}/authorize`,
            tokenEndpoint: tokenEndpoint || `${providerUrl}/oauth/token`,
            deviceAuthorizationEndpoint: `${providerUrl}/oauth/device/code`,
            jwksUrl: `${providerUrl}/.well-known/jwks.json`,
            userInfoUrl: userInfoEndpoint || `${providerUrl}/userinfo`,
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