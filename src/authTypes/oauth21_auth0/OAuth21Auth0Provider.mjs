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


    getDiscoveryMetadata( { config } ) {
        const { providerUrl, scope } = config

        // Parse scopes from space-separated string to array
        const scopes = scope ? scope.split( ' ' ) : []

        const metadata = {
            issuer: `${providerUrl}`,  // Auth0 issuer (base URL)
            authorization_endpoint: `${providerUrl}/authorize`,  // Auth0 uses /authorize (not /oauth/authorize)
            token_endpoint: `${providerUrl}/oauth/token`,
            userinfo_endpoint: `${providerUrl}/userinfo`,
            jwks_uri: `${providerUrl}/.well-known/jwks.json`,  // Auth0 JWKS endpoint
            // Auth0 requires pre-registered clients, registration endpoint would be at tenant level
            registration_endpoint: `${config.baseUrl || 'http://localhost:3001'}/auth0-route/oauth/register`,
            scopes_supported: scopes,
            response_types_supported: [ 'code' ],
            response_modes_supported: [ 'query', 'form_post' ],
            grant_types_supported: [ 'authorization_code', 'client_credentials', 'refresh_token' ],
            code_challenge_methods_supported: [ 'S256' ],
            token_endpoint_auth_methods_supported: [ 'client_secret_basic', 'client_secret_post' ],
            subject_types_supported: [ 'public' ],
            claims_supported: [ 'sub', 'iat', 'exp', 'aud', 'iss', 'scope', 'email', 'email_verified', 'name', 'picture' ]
        }

        if( !this.#silent ) {
            Logger.info( {
                silent: this.#silent,
                message: `Generated Auth0 discovery metadata`
            } )
        }

        return {
            success: true,
            metadata
        }
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