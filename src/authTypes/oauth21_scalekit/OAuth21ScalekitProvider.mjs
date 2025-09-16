import { Logger } from '../../helpers/Logger.mjs'
import { oauth21ScalekitSchema } from './OAuth21ScalekitSchema.mjs'


class OAuth21ScalekitProvider {
    #config
    #silent


    constructor( { config, silent = false } ) {
        this.#config = config
        this.#silent = silent
    }


    detectProviderType( { providerUrl } ) {
        // Support both ScaleKit hosted domains and custom domains
        // Explicitly exclude auth0.com to avoid confusion with Auth0 provider
        return !!(providerUrl && !providerUrl.includes( 'auth0.com' ))
    }


    normalizeConfiguration( { config } ) {
        // Preserve all original config fields and only add/override provider-specific ones
        const normalizedConfig = {
            ...config,  // Keep all Entry-Point defaults and user config
            authFlow: 'authorization_code',  // Provider-specific constant
            authType: 'oauth21_scalekit'     // Provider-specific constant
        }

        // Ensure resourceDocumentation has a default if not provided
        if( !normalizedConfig.resourceDocumentation && normalizedConfig.resource ) {
            normalizedConfig.resourceDocumentation = `${normalizedConfig.resource}/docs`
        }

        return { normalizedConfig }
    }


    generateEndpoints( { config } ) {
        const { providerUrl, mcpId, tokenEndpoint, userInfoEndpoint } = config

        const endpoints = {
            // OAuth 2.1 endpoints for ScaleKit (corrected based on discovery)
            authorizationEndpoint: `${providerUrl}/oauth/authorize`,
            tokenEndpoint: tokenEndpoint || `${providerUrl}/oauth/token`,
            deviceAuthorizationEndpoint: `${providerUrl}/oauth/device/code`,
            jwksUrl: `${providerUrl}/keys`,  // Correct ScaleKit JWKS endpoint
            userInfoUrl: userInfoEndpoint || `${providerUrl}/userinfo`,
            introspectionUrl: `${providerUrl}/oauth/introspect`,
            discoveryUrl: `${providerUrl}/.well-known/openid-configuration`,
            // ScaleKit does NOT provide a registration endpoint - clients must be pre-registered
            // ScaleKit-specific resource endpoint
            resourceUrl: `${providerUrl}/resources/${mcpId}`
        }

        return { endpoints }
    }


    generateProtectedResourceMetadata( { config } ) {
        const {
            providerUrl,
            mcpId,
            resource,
            resourceDocumentation,
            scope
        } = config

        // Parse scopes from space-separated string to array
        const scopes = scope ? scope.split( ' ' ) : []

        const metadata = {
            authorization_servers: [ `${providerUrl}/resources/${mcpId}` ],
            bearer_methods_supported: [ 'header' ],
            resource,
            resource_documentation: resourceDocumentation || `${resource}/docs`,
            scopes_supported: scopes
        }

        if( !this.#silent ) {
            Logger.info( {
                silent: this.#silent,
                message: `Generated ScaleKit protected resource metadata for ${resource}`
            } )
        }

        return {
            success: true,
            metadata
        }
    }


    getDiscoveryMetadata( { config } ) {
        const { providerUrl, mcpId, scope } = config

        // Parse scopes from space-separated string to array
        const scopes = scope ? scope.split( ' ' ) : []

        const metadata = {
            issuer: `${providerUrl}`,  // Correct ScaleKit issuer (base URL)
            authorization_endpoint: `${providerUrl}/oauth/authorize`,
            token_endpoint: `${providerUrl}/oauth/token`,
            userinfo_endpoint: `${providerUrl}/userinfo`,
            jwks_uri: `${providerUrl}/keys`,  // Correct ScaleKit JWKS endpoint
            // ScaleKit requires pre-registered clients, but we provide a registration endpoint
            // that returns the pre-configured credentials for MCP clients
            registration_endpoint: `${config.baseUrl || 'http://localhost:3001'}/scalekit-route/oauth/register`,
            scopes_supported: scopes,
            response_types_supported: [ 'code' ],
            response_modes_supported: [ 'query', 'form_post' ],
            grant_types_supported: [ 'authorization_code', 'client_credentials', 'refresh_token' ],
            code_challenge_methods_supported: [ 'S256' ],
            token_endpoint_auth_methods_supported: [ 'client_secret_basic', 'client_secret_post' ],
            subject_types_supported: [ 'public' ],
            claims_supported: [ 'sub', 'iat', 'exp', 'aud', 'iss', 'scope' ]
        }

        if( !this.#silent ) {
            Logger.info( {
                silent: this.#silent,
                message: `Generated ScaleKit discovery metadata`
            } )
        }

        return {
            success: true,
            metadata
        }
    }


    generateAuthorizationServerMetadata( { config } ) {
        // Delegate to the new standardized method
        return this.getDiscoveryMetadata( { config } )
    }


    static validateOAuth21ScalekitConfig( { config } ) {
        const struct = { status: false, messages: [] }

        if( !config || typeof config !== 'object' ) {
            struct['messages'].push( 'OAuth21Scalekit config must be a valid object' )
            return struct
        }

        const requiredFields = [ 'providerUrl', 'mcpId', 'clientId', 'clientSecret', 'resource', 'scope' ]
        const missing = requiredFields.filter( field => !config[field] )

        if( missing.length > 0 ) {
            struct['messages'].push( `OAuth21Scalekit config missing required fields: ${missing.join( ', ' )}` )
        }

        // Custom domains are now supported - no domain restriction

        // Validate using schema patterns
        const { validation } = oauth21ScalekitSchema
        if( config.providerUrl && validation.providerUrl.pattern && !validation.providerUrl.pattern.test( config.providerUrl ) ) {
            struct['messages'].push( `OAuth21Scalekit config validation failed: ${validation.providerUrl.message}` )
        }

        if( config.mcpId && !config.mcpId.startsWith( 'res_' ) ) {
            struct['messages'].push( 'OAuth21Scalekit mcpId must start with "res_"' )
        }

        if( config.scope && typeof config.scope !== 'string' ) {
            struct['messages'].push( 'OAuth21Scalekit scope must be a string' )
        }

        if( config.resource && typeof config.resource !== 'string' ) {
            struct['messages'].push( 'OAuth21Scalekit resource must be a string' )
        }

        struct['status'] = struct['messages'].length === 0
        return struct
    }


    getProviderName() {
        return 'oauth21_scalekit'
    }


    getDisplayName() {
        return 'OAuth 2.1 with ScaleKit'
    }


    static getSupportedFlows() {
        return [ 'authorization_code', 'client_credentials', 'refresh_token' ]
    }


    static getDefaultScopes() {
        return 'mcp:tools:* mcp:resources:read mcp:resources:write'
    }


    static isMcpProvider() {
        return true
    }
}

export { OAuth21ScalekitProvider }