import fetch from 'node-fetch'
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
        Object.entries( routes ).forEach( ( [ route, config ] ) => {
            const normalizedConfig = {
                providerUrl: config.providerUrl,
                realm: config.realm,
                clientId: config.clientId,
                clientSecret: config.clientSecret,
                redirectUri: `${baseRedirectUri}${route}/callback`,
                authFlow: config.authFlow || 'authorization_code',
                requiredScopes: config.requiredScopes || [],
                forceHttps: config.forceHttps,
                resourceUri: config.resourceUri || '',
                authorizationEndpoint: config.authorizationUrl || (config.providerUrl.includes('auth0.com') ? 
                    `${config.providerUrl}/authorize` : 
                    `${config.providerUrl}/realms/${config.realm}/protocol/openid-connect/auth`),
                tokenEndpoint: config.tokenUrl || (config.providerUrl.includes('auth0.com') ? 
                    `${config.providerUrl}/oauth/token` : 
                    `${config.providerUrl}/realms/${config.realm}/protocol/openid-connect/token`),
                deviceAuthorizationEndpoint: config.providerUrl.includes('auth0.com') ? 
                    `${config.providerUrl}/oauth/device/code` : 
                    `${config.providerUrl}/realms/${config.realm}/protocol/openid-connect/auth/device`
            }
            
            handler.#routeConfigs.set( route, normalizedConfig )
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


    static create( { providerUrl, realm, clientId, clientSecret, redirectUri, silent = false } ) {
        const handler = new OAuthFlowHandler( { silent } )
        
        const config = {
            providerUrl,
            realm,
            clientId,
            clientSecret,
            redirectUri,
            authorizationEndpoint: providerUrl.includes('auth0.com') ? 
                `${providerUrl}/authorize` : 
                `${providerUrl}/realms/${realm}/protocol/openid-connect/auth`,
            tokenEndpoint: providerUrl.includes('auth0.com') ? 
                `${providerUrl}/oauth/token` : 
                `${providerUrl}/realms/${realm}/protocol/openid-connect/token`,
            deviceAuthorizationEndpoint: providerUrl.includes('auth0.com') ? 
                `${providerUrl}/oauth/device/code` : 
                `${providerUrl}/realms/${realm}/protocol/openid-connect/auth/device`
        }
        
        // For backwards compatibility - store as single route
        handler.#routeConfigs.set( 'default', config )

        return handler
    }


    initiateAuthorizationCodeFlowForRoute( { route, scopes = [ 'openid' ], resourceIndicators = [] } ) {
        const config = this.#getConfigForRoute( { route } )
        const state = crypto.randomBytes( 16 ).toString( 'base64url' )
        const { pair } = PKCEGenerator.generatePKCEPair()
        
        // Use route-specific resource URI if not provided
        const effectiveResourceIndicators = resourceIndicators.length > 0 
            ? resourceIndicators 
            : config.resourceUri ? [ config.resourceUri ] : []
            
        const authRequest = {
            state,
            route,
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
            message: `Authorization URL for route ${route}: ${authorizationUrl}` 
        } )

        return { authorizationUrl, state, route }
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
            route: authRequest.route,
            codeVerifier: authRequest.codeVerifier,
            resourceIndicators: authRequest.resourceIndicators
        } )
        
        this.#authorizationRequests.delete( state )
        
        return { 
            success: true, 
            tokens,
            route: authRequest.route,
            resourceIndicators: authRequest.resourceIndicators
        }
    }


    async requestClientCredentialsForRoute( { route, scopes = [] } ) {
        const config = this.#getConfigForRoute( { route } )
        
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
            message: `Client credentials obtained for route ${route}` 
        } )

        return { tokens, route }
    }


    async refreshAccessTokenForRoute( { refreshToken, route, resourceIndicators = [] } ) {
        const config = this.#getConfigForRoute( { route } )
        
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
                route 
            }
        }

        return { 
            success: true, 
            tokens,
            route
        }
    }


    // Backwards compatibility methods
    initiateAuthorizationCodeFlow( { scopes = [ 'openid' ], resourceIndicators = [] } ) {
        return this.initiateAuthorizationCodeFlowForRoute( { route: 'default', scopes, resourceIndicators } )
    }


    async handleAuthorizationCallback( { code, state } ) {
        return this.handleAuthorizationCallbackForRoute( { code, state } )
    }


    async requestClientCredentials( { scopes = [] } ) {
        return this.requestClientCredentialsForRoute( { route: 'default', scopes } )
    }


    async refreshAccessToken( { refreshToken } ) {
        return this.refreshAccessTokenForRoute( { refreshToken, route: 'default' } )
    }


    #getConfigForRoute( { route } ) {
        const config = this.#routeConfigs.get( route )
        
        if( !config ) {
            throw new Error( `No configuration found for route: ${route}` )
        }

        return config
    }


    getAllRoutes() {
        return Array.from( this.#routeConfigs.keys() )
    }


    getRouteConfig( { route } ) {
        return this.#getConfigForRoute( { route } )
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


    async #exchangeCodeForTokensForRoute( { code, route, codeVerifier, resourceIndicators = [] } ) {
        const config = this.#getConfigForRoute( { route } )
        
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
        return this.#exchangeCodeForTokensForRoute( { code, route: 'default', codeVerifier } )
    }
}

export { OAuthFlowHandler }