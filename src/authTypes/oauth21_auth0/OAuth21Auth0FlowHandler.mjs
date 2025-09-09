// Using native fetch (Node.js 22+)
import crypto from 'crypto'

import { Logger } from '../../helpers/Logger.mjs'
import { PKCEGenerator } from '../../helpers/PKCEGenerator.mjs'


class OAuth21Auth0FlowHandler {
    #config
    #silent
    #authorizationRequests
    #endpoints


    constructor( { config, silent = false } ) {
        this.#config = config
        this.#silent = silent
        this.#authorizationRequests = new Map()
        
        this.#initializeEndpoints()
    }


    static createForAuth0( { config, redirectUri, silent = false } ) {
        const enhancedConfig = {
            ...config,
            redirectUri: redirectUri || `${config.baseUrl || 'http://localhost:3000'}/auth/callback`
        }
        
        return new OAuth21Auth0FlowHandler( { config: enhancedConfig, silent } )
    }


    initiateAuthorizationCodeFlow( { scopes, audience, state } ) {
        const authState = state || crypto.randomBytes( 16 ).toString( 'base64url' )
        const { pair } = PKCEGenerator.generatePKCEPair()
        
        const effectiveScopes = scopes || this.#config.scope || 'openid profile email'
        const effectiveAudience = audience || this.#config.audience
        
        const authRequest = {
            state: authState,
            codeVerifier: pair.codeVerifier,
            codeChallenge: pair.codeChallenge,
            codeChallengeMethod: pair.codeChallengeMethod,
            scopes: effectiveScopes,
            audience: effectiveAudience,
            timestamp: Date.now(),
            authType: 'oauth21_auth0'
        }
        
        this.#authorizationRequests.set( authState, authRequest )
        
        const params = new URLSearchParams( {
            response_type: this.#config.responseType || 'code',
            client_id: this.#config.clientId,
            redirect_uri: this.#config.redirectUri,
            scope: effectiveScopes,
            state: authState,
            code_challenge: pair.codeChallenge,
            code_challenge_method: pair.codeChallengeMethod
        } )
        
        if( effectiveAudience ) {
            params.append( 'audience', effectiveAudience )
        }
        
        const authorizationUrl = `${this.#endpoints.authorizationEndpoint}?${params.toString()}`
        
        if( !this.#silent ) {
            Logger.info( { 
                silent: this.#silent, 
                message: `OAuth21Auth0 authorization URL generated: ${authorizationUrl}` 
            } )
        }

        return { authorizationUrl, state: authState, authType: 'oauth21_auth0' }
    }


    async handleAuthorizationCallback( { code, state } ) {
        const authRequest = this.#authorizationRequests.get( state )
        
        if( !authRequest ) {
            return { 
                success: false, 
                error: 'Invalid state parameter',
                authType: 'oauth21_auth0'
            }
        }
        
        const { tokens } = await this.#exchangeCodeForTokens( { 
            code, 
            codeVerifier: authRequest.codeVerifier,
            audience: authRequest.audience
        } )
        
        this.#authorizationRequests.delete( state )
        
        if( tokens.error ) {
            return { 
                success: false, 
                error: tokens.error_description || tokens.error,
                authType: 'oauth21_auth0'
            }
        }
        
        return { 
            success: true, 
            tokens,
            authType: 'oauth21_auth0',
            audience: authRequest.audience
        }
    }


    async requestClientCredentials( { scopes, audience } ) {
        const params = new URLSearchParams( {
            grant_type: 'client_credentials',
            client_id: this.#config.clientId,
            client_secret: this.#config.clientSecret
        } )
        
        const effectiveScopes = scopes || this.#config.scope
        if( effectiveScopes ) {
            params.append( 'scope', effectiveScopes )
        }
        
        const effectiveAudience = audience || this.#config.audience
        if( effectiveAudience ) {
            params.append( 'audience', effectiveAudience )
        }
        
        const response = await fetch( this.#endpoints.tokenEndpoint, {
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
                error: tokens.error_description || tokens.error,
                authType: 'oauth21_auth0'
            }
        }
        
        if( !this.#silent ) {
            Logger.info( { 
                silent: this.#silent, 
                message: 'OAuth21Auth0 client credentials obtained successfully' 
            } )
        }

        return { 
            success: true, 
            tokens,
            authType: 'oauth21_auth0',
            audience: effectiveAudience
        }
    }


    async refreshAccessToken( { refreshToken, audience } ) {
        const params = new URLSearchParams( {
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: this.#config.clientId,
            client_secret: this.#config.clientSecret
        } )
        
        const effectiveAudience = audience || this.#config.audience
        if( effectiveAudience ) {
            params.append( 'audience', effectiveAudience )
        }
        
        const response = await fetch( this.#endpoints.tokenEndpoint, {
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
                error: tokens.error_description || tokens.error,
                authType: 'oauth21_auth0'
            }
        }

        return { 
            success: true, 
            tokens,
            authType: 'oauth21_auth0',
            audience: effectiveAudience
        }
    }


    async discoverConfiguration() {
        try {
            const response = await fetch( this.#endpoints.discoveryUrl )
            const config = await response.json()

            if( !this.#silent ) {
                Logger.info( { 
                    silent: this.#silent, 
                    message: 'OAuth21Auth0 configuration discovered successfully' 
                } )
            }

            return { 
                success: true, 
                config,
                authType: 'oauth21_auth0'
            }
        } catch( error ) {
            return { 
                success: false, 
                error: error.message,
                authType: 'oauth21_auth0'
            }
        }
    }


    #initializeEndpoints() {
        const { providerUrl } = this.#config
        
        this.#endpoints = {
            authorizationEndpoint: `${providerUrl}/authorize`,
            tokenEndpoint: this.#config.tokenEndpoint || `${providerUrl}/oauth/token`,
            deviceAuthorizationEndpoint: `${providerUrl}/oauth/device/code`,
            jwksUrl: `${providerUrl}/.well-known/jwks.json`,
            userInfoUrl: this.#config.userInfoEndpoint || `${providerUrl}/userinfo`,
            introspectionUrl: `${providerUrl}/oauth/token/introspection`,
            discoveryUrl: `${providerUrl}/.well-known/openid_configuration`
        }

        if( !this.#silent ) {
            Logger.info( { 
                silent: this.#silent, 
                message: `OAuth21Auth0FlowHandler initialized for provider: ${providerUrl}` 
            } )
        }
    }


    async #exchangeCodeForTokens( { code, codeVerifier, audience } ) {
        const params = new URLSearchParams( {
            grant_type: 'authorization_code',
            code,
            redirect_uri: this.#config.redirectUri,
            client_id: this.#config.clientId,
            client_secret: this.#config.clientSecret,
            code_verifier: codeVerifier
        } )
        
        if( audience ) {
            params.append( 'audience', audience )
        }
        
        const response = await fetch( this.#endpoints.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        } )
        
        const tokens = await response.json()

        return { tokens }
    }


    clearExpiredAuthRequests() {
        const now = Date.now()
        const expiredStates = Array.from( this.#authorizationRequests.entries() )
            .filter( ( [ state, request ] ) => now - request.timestamp > 600000 ) // 10 minutes
            .map( ( [ state ] ) => state )
        
        expiredStates.forEach( ( state ) => {
            this.#authorizationRequests.delete( state )
        } )

        if( expiredStates.length > 0 && !this.#silent ) {
            Logger.info( { 
                silent: this.#silent, 
                message: `OAuth21Auth0FlowHandler cleared ${expiredStates.length} expired authorization requests` 
            } )
        }
    }


    getEndpoints() {
        return { ...this.#endpoints }
    }


    getConfig() {
        return { ...this.#config }
    }


    getAuthType() {
        return 'oauth21_auth0'
    }
}

export { OAuth21Auth0FlowHandler }