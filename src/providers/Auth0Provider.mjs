import { BaseProvider } from './BaseProvider.mjs'


class Auth0Provider extends BaseProvider {
    constructor( { config, silent = false } ) {
        super( { config, silent } )
    }


    detectProviderType( { providerUrl } ) {
        return !!(providerUrl && providerUrl.includes( 'auth0.com' ))
    }


    normalizeConfiguration( { config } ) {
        const { providerUrl, realm, clientId, clientSecret, requiredScopes, resourceUri } = config
        
        const normalizedConfig = {
            providerUrl,
            realm: realm || 'auth0',
            clientId,
            clientSecret,
            requiredScopes: requiredScopes || [ 'openid', 'profile', 'email' ],
            resourceUri,
            authFlow: 'authorization_code'
        }

        return { normalizedConfig }
    }


    generateEndpoints( { config } ) {
        const { providerUrl } = config
        
        const endpoints = {
            authorizationEndpoint: `${providerUrl}/authorize`,
            tokenEndpoint: `${providerUrl}/oauth/token`,
            deviceAuthorizationEndpoint: `${providerUrl}/oauth/device/code`,
            jwksUrl: `${providerUrl}/.well-known/jwks.json`,
            userInfoUrl: `${providerUrl}/userinfo`,
            introspectionUrl: `${providerUrl}/oauth/token/introspection`,
            discoveryUrl: `${providerUrl}/.well-known/openid_configuration`
        }

        return { endpoints }
    }


    static validateAuth0Config( { config } ) {
        const struct = { status: false, messages: [] }

        if( !config || typeof config !== 'object' ) {
            struct['messages'].push( 'Auth0 config must be a valid object' )
            return struct
        }

        const requiredFields = [ 'providerUrl', 'clientId', 'clientSecret' ]
        const missing = requiredFields.filter( field => !config[field] )
        
        if( missing.length > 0 ) {
            struct['messages'].push( `Auth0 config missing required fields: ${missing.join( ', ' )}` )
        }

        if( config.providerUrl && !config.providerUrl.includes( 'auth0.com' ) ) {
            struct['messages'].push( 'Auth0 provider requires auth0.com domain in providerUrl' )
        }

        if( config.requiredScopes && !Array.isArray( config.requiredScopes ) ) {
            struct['messages'].push( 'Auth0 requiredScopes must be an array' )
        }

        struct['status'] = struct['messages'].length === 0
        return struct
    }


    getProviderName() {
        return 'auth0'
    }


    getDisplayName() {
        return 'Auth0'
    }


    static getSupportedFlows() {
        return [ 'authorization_code', 'client_credentials', 'refresh_token' ]
    }


    static getDefaultScopes() {
        return [ 'openid', 'profile', 'email' ]
    }
}


export { Auth0Provider }