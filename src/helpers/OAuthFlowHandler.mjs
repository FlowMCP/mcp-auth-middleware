// Using native fetch (Node.js 22+)
import crypto from 'crypto'

import { Logger } from './Logger.mjs'
import { PKCEGenerator } from './PKCEGenerator.mjs'


class OAuthFlowHandler {
    #routeConfigs
    #silent
    #authorizationRequests


    constructor( { silent = false } ) {
        this.#silent = silent
        this.#routeConfigs = new Map()
        this.#authorizationRequests = new Map()
    }


    static createForMultiRealm( { routes, baseRedirectUri, silent = false } ) {
        const handler = new OAuthFlowHandler( { silent } )
        
        // Initialize all route configurations
        Object.entries( routes ).forEach( ( [ routePath, config ] ) => {
            // OAuthFlowHandler supports OAuth-based auth types (staticBearer has no OAuth flow)
            if( !['oauth21_auth0', 'oauth21_scalekit'].includes(config.authType) ) {
                throw new Error( `OAuthFlowHandler only supports oauth21_auth0, oauth21_scalekit, got: ${config.authType}` )
            }

            const normalizedConfig = {
                providerUrl: config.providerUrl,
                realm: config.realm, // Auth0-specific
                mcpId: config.mcpId, // ScaleKit-specific
                resource: config.resource, // ScaleKit-specific
                clientId: config.clientId,
                clientSecret: config.clientSecret,
                redirectUri: `${baseRedirectUri}${routePath}/auth/callback`,
                authFlow: config.authFlow,
                requiredScopes: config.requiredScopes,
                forceHttps: config.forceHttps,
                resourceUri: config.resourceUri, // Auth0-specific
                // URLs will be handled by AuthType handlers
                authorizationEndpoint: config.authorizationEndpoint,
                tokenEndpoint: config.tokenEndpoint,
                deviceAuthorizationEndpoint: config.deviceAuthorizationEndpoint
            }
            
            handler.#routeConfigs.set( routePath, normalizedConfig )
        } )

        return handler
    }


    getDiscoveryData() {
        // Get first route configuration to derive discovery metadata
        const firstRoute = Array.from( this.#routeConfigs.values() )[0]
        
        if( !firstRoute ) {
            throw new Error( 'No route configurations available for discovery data' )
        }
        
        // Build OAuth Authorization Server metadata (RFC 8414)
        const discoveryData = {
            issuer: firstRoute.providerUrl,
            authorization_endpoint: firstRoute.authorizationEndpoint,
            token_endpoint: firstRoute.tokenEndpoint,
            jwks_uri: `${firstRoute.providerUrl}/.well-known/jwks.json`,
            
            // Supported methods and parameters
            scopes_supported: [ 'openid', 'profile', 'email' ],
            response_types_supported: [ 'code' ],
            response_modes_supported: [ 'query', 'form_post' ],
            grant_types_supported: [ 'authorization_code' ],
            
            // PKCE support (OAuth 2.1 requirement)
            code_challenge_methods_supported: [ 'S256' ],
            
            // Token endpoint authentication methods
            token_endpoint_auth_methods_supported: [ 'client_secret_basic', 'client_secret_post' ],
            
            // Claims and features
            claims_supported: [ 'sub', 'iat', 'exp', 'aud', 'iss', 'scope' ],
            subject_types_supported: [ 'public' ]
        }
        
        return discoveryData
    }


    static create( { providerUrl, realm, clientId, clientSecret, redirectUri, authType = 'oauth21_auth0', silent = false, authorizationEndpoint = null, tokenEndpoint = null, deviceAuthorizationEndpoint = null } ) {
        const handler = new OAuthFlowHandler( { silent } )

        // Require oauth21_auth0 authType
        if( authType !== 'oauth21_auth0' ) {
            throw new Error( `OAuthFlowHandler.create() only supports oauth21_auth0, got: ${authType}` )
        }

        const config = {
            providerUrl,
            realm,
            clientId,
            clientSecret,
            redirectUri,
            authType,
            // URLs provided by AuthType handlers
            authorizationEndpoint,
            tokenEndpoint,
            deviceAuthorizationEndpoint
        }

        // For backwards compatibility - store as single route
        handler.#routeConfigs.set( 'default', config )

        return handler
    }


    initiateAuthorizationCodeFlowForRoute( { routePath, scopes = [ 'openid' ], resourceIndicators = [] } ) {
        const config = this.#getConfigForRoute( { routePath } )
        const state = crypto.randomBytes( 16 ).toString( 'base64url' )
        const { pair } = PKCEGenerator.generatePKCEPair()
        
        // Use route-specific resource URI if not provided
        const effectiveResourceIndicators = resourceIndicators.length > 0 
            ? resourceIndicators 
            : config.resourceUri ? [ config.resourceUri ] : []
            
        const authRequest = {
            state,
            routePath,
            codeVerifier: pair.codeVerifier,
            codeChallenge: pair.codeChallenge,
            codeChallengeMethod: pair.codeChallengeMethod,
            scopes,
            resourceIndicators: effectiveResourceIndicators,
            timestamp: Date.now()
        }
        
        this.#authorizationRequests.set( state, authRequest )
        
        const params = new URLSearchParams( {
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: scopes.join( ' ' ),
            state,
            code_challenge: pair.codeChallenge,
            code_challenge_method: pair.codeChallengeMethod
        } )
        
        // RFC 8707: Resource Indicators
        if( effectiveResourceIndicators.length > 0 ) {
            effectiveResourceIndicators.forEach( ( resource ) => {
                params.append( 'resource', resource )
            } )
        }
        
        const authorizationUrl = `${config.authorizationEndpoint}?${params.toString()}`
        
        Logger.info( { 
            silent: this.#silent, 
            message: `Authorization URL for route ${routePath}: ${authorizationUrl}` 
        } )

        return { authorizationUrl, state, routePath }
    }


    async handleAuthorizationCallbackForRoute( { code, state } ) {
        const authRequest = this.#authorizationRequests.get( state )
        
        if( !authRequest ) {
            return { 
                success: false, 
                error: 'Invalid state parameter' 
            }
        }
        
        const { tokens } = await this.#exchangeCodeForTokensForRoute( { 
            code, 
            routePath: authRequest.routePath,
            codeVerifier: authRequest.codeVerifier,
            resourceIndicators: authRequest.resourceIndicators
        } )
        
        this.#authorizationRequests.delete( state )
        
        return { 
            success: true, 
            tokens,
            routePath: authRequest.routePath,
            resourceIndicators: authRequest.resourceIndicators
        }
    }


    async requestClientCredentialsForRoute( { routePath, scopes = [] } ) {
        const config = this.#getConfigForRoute( { routePath } )
        
        const params = new URLSearchParams( {
            grant_type: 'client_credentials',
            client_id: config.clientId,
            client_secret: config.clientSecret
        } )
        
        // Use route's required scopes if not provided
        const effectiveScopes = scopes.length > 0 ? scopes : config.requiredScopes
        if( effectiveScopes.length > 0 ) {
            params.append( 'scope', effectiveScopes.join( ' ' ) )
        }
        
        // RFC 8707: Resource parameter for client credentials
        if( config.resourceUri ) {
            params.append( 'resource', config.resourceUri )
        }
        
        const response = await fetch( config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        } )
        
        const tokens = await response.json()
        
        Logger.info( { 
            silent: this.#silent, 
            message: `Client credentials obtained for route ${routePath}` 
        } )

        return { tokens, routePath }
    }


    async refreshAccessTokenForRoute( { refreshToken, routePath, resourceIndicators = [] } ) {
        const config = this.#getConfigForRoute( { routePath } )
        
        const params = new URLSearchParams( {
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: config.clientId,
            client_secret: config.clientSecret
        } )
        
        // RFC 8707: Include resource parameters in refresh token request
        if( resourceIndicators && resourceIndicators.length > 0 ) {
            resourceIndicators.forEach( ( resource ) => {
                params.append( 'resource', resource )
            } )
        } else if( config.resourceUri ) {
            // Fallback to route-specific resource URI
            params.append( 'resource', config.resourceUri )
        }
        
        const response = await fetch( config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        } )
        
        const tokens = await response.json()
        
        if( tokens.error ) {
            return { 
                success: false, 
                error: tokens.error_description || 'Token refresh failed',
                routePath 
            }
        }

        return { 
            success: true, 
            tokens,
            routePath
        }
    }


    // Backwards compatibility methods
    initiateAuthorizationCodeFlow( { scopes = [ 'openid' ], resourceIndicators = [] } ) {
        return this.initiateAuthorizationCodeFlowForRoute( { routePath: 'default', scopes, resourceIndicators } )
    }


    async handleAuthorizationCallback( { code, state } ) {
        return this.handleAuthorizationCallbackForRoute( { code, state } )
    }


    async requestClientCredentials( { scopes = [] } ) {
        return this.requestClientCredentialsForRoute( { routePath: 'default', scopes } )
    }


    async refreshAccessToken( { refreshToken } ) {
        return this.refreshAccessTokenForRoute( { refreshToken, routePath: 'default' } )
    }


    #getConfigForRoute( { routePath } ) {
        const config = this.#routeConfigs.get( routePath )
        
        if( !config ) {
            throw new Error( `No configuration found for route: ${routePath}` )
        }

        return config
    }


    getAllRoutes() {
        return Array.from( this.#routeConfigs.keys() )
    }


    getRouteConfig( { routePath } ) {
        return this.#getConfigForRoute( { routePath } )
    }


    clearExpiredAuthRequests() {
        const now = Date.now()
        const expiredStates = Array.from( this.#authorizationRequests.entries() )
            .filter( ( [ state, request ] ) => now - request.timestamp > 600000 ) // 10 minutes
            .map( ( [ state ] ) => state )
        
        expiredStates.forEach( ( state ) => {
            this.#authorizationRequests.delete( state )
        } )

        if( expiredStates.length > 0 ) {
            Logger.info( { 
                silent: this.#silent, 
                message: `Cleared ${expiredStates.length} expired authorization requests` 
            } )
        }
    }


    async #exchangeCodeForTokensForRoute( { code, routePath, codeVerifier, resourceIndicators = [] } ) {
        const config = this.#getConfigForRoute( { routePath } )
        
        const params = new URLSearchParams( {
            grant_type: 'authorization_code',
            code,
            redirect_uri: config.redirectUri,
            client_id: config.clientId,
            code_verifier: codeVerifier
        } )
        
        if( config.clientSecret ) {
            params.append( 'client_secret', config.clientSecret )
        }
        
        // RFC 8707: Include resource parameters in token request
        if( resourceIndicators && resourceIndicators.length > 0 ) {
            resourceIndicators.forEach( ( resource ) => {
                params.append( 'resource', resource )
            } )
        } else if( config.resourceUri ) {
            // Fallback to route-specific resource URI
            params.append( 'resource', config.resourceUri )
        }
        
        const response = await fetch( config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        } )
        
        const tokens = await response.json()

        return { tokens }
    }


    // Backwards compatibility
    async #exchangeCodeForTokens( { code, codeVerifier } ) {
        return this.#exchangeCodeForTokensForRoute( { code, routePath: 'default', codeVerifier } )
    }
}

export { OAuthFlowHandler }