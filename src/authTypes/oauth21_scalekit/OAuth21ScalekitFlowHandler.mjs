import { URLSearchParams } from 'url'

import { Logger } from '../../helpers/Logger.mjs'
import { PKCEGenerator } from '../../helpers/PKCEGenerator.mjs'


class OAuth21ScalekitFlowHandler {
    #config
    #endpoints
    #silent
    #stateStorage


    constructor( { config, silent = false } ) {
        this.#config = config
        this.#silent = silent
        this.#stateStorage = new Map()

        // Generate endpoints from provider
        const { endpoints } = config
        this.#endpoints = endpoints || this.#generateDefaultEndpoints()
    }


    static createForScalekit( { config, silent = false } ) {
        return new OAuth21ScalekitFlowHandler( { config, silent } )
    }


    initiateAuthFlow( { scopes, redirectUri, state } ) {
        const { pair } = PKCEGenerator.generatePKCEPair()
        const { codeChallenge, codeVerifier } = pair

        // Generate state if not provided
        const authState = state || this.#generateState()

        // Store PKCE verifier and original state for callback
        this.#stateStorage.set( authState, {
            codeVerifier,
            redirectUri,
            originalState: state,
            timestamp: Date.now()
        } )

        const authParams = new URLSearchParams( {
            response_type: 'code',
            client_id: this.#config.clientId,
            redirect_uri: redirectUri,
            scope: scopes || this.#config.scope,
            state: authState,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            // ScaleKit-specific: include resource in authorization request
            audience: this.#config.resource
        } )

        const authorizationUrl = `${this.#endpoints.authorizationEndpoint}?${authParams.toString()}`

        Logger.info( {
            silent: this.#silent,
            message: `Initiated ScaleKit auth flow for resource: ${this.#config.resource}`
        } )

        return {
            authorizationUrl,
            state: authState,
            codeChallenge,
            redirectUri
        }
    }


    async handleCallback( { code, state, redirectUri } ) {
        const storedState = this.#stateStorage.get( state )

        if( !storedState ) {
            return {
                success: false,
                error: 'Invalid or expired state parameter',
                errorCode: 'invalid_state'
            }
        }

        const { codeVerifier, originalState } = storedState

        // Clean up state storage
        this.#stateStorage.delete( state )

        try {
            const tokenResponse = await this.#exchangeCodeForTokens( {
                code,
                redirectUri: redirectUri || storedState.redirectUri,
                codeVerifier
            } )

            if( !tokenResponse.success ) {
                return tokenResponse
            }

            return {
                success: true,
                tokens: tokenResponse.tokens,
                state: originalState,
                tokenType: 'Bearer',
                expiresIn: tokenResponse.tokens.expires_in
            }

        } catch( error ) {
            Logger.error( {
                silent: this.#silent,
                message: `ScaleKit callback error: ${error.message}`
            } )

            return {
                success: false,
                error: 'Token exchange failed',
                errorCode: 'token_exchange_failed',
                details: error.message
            }
        }
    }


    async refreshToken( { refreshToken } ) {
        const tokenParams = new URLSearchParams( {
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: this.#config.clientId,
            client_secret: this.#config.clientSecret
        } )

        try {
            const response = await fetch( this.#endpoints.tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: tokenParams.toString()
            } )

            if( !response.ok ) {
                const errorData = await response.json().catch( () => ( {} ) )
                return {
                    success: false,
                    error: errorData.error || 'Token refresh failed',
                    errorDescription: errorData.error_description
                }
            }

            const tokens = await response.json()

            Logger.info( {
                silent: this.#silent,
                message: 'Successfully refreshed ScaleKit token'
            } )

            return {
                success: true,
                tokens
            }

        } catch( error ) {
            return {
                success: false,
                error: 'Network error during token refresh',
                details: error.message
            }
        }
    }


    async getClientCredentialsToken( { scope } ) {
        // Machine-to-machine authentication for MCP servers
        const tokenParams = new URLSearchParams( {
            grant_type: 'client_credentials',
            client_id: this.#config.clientId,
            client_secret: this.#config.clientSecret,
            scope: scope || this.#config.scope,
            audience: this.#config.resource
        } )

        try {
            const response = await fetch( this.#endpoints.tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: tokenParams.toString()
            } )

            if( !response.ok ) {
                const errorData = await response.json().catch( () => ( {} ) )
                return {
                    success: false,
                    error: errorData.error || 'Client credentials grant failed',
                    errorDescription: errorData.error_description
                }
            }

            const tokens = await response.json()

            Logger.info( {
                silent: this.#silent,
                message: 'Successfully obtained ScaleKit client credentials token'
            } )

            return {
                success: true,
                tokens,
                tokenType: 'Bearer'
            }

        } catch( error ) {
            return {
                success: false,
                error: 'Network error during client credentials grant',
                details: error.message
            }
        }
    }


    async #exchangeCodeForTokens( { code, redirectUri, codeVerifier } ) {
        const tokenParams = new URLSearchParams( {
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            client_id: this.#config.clientId,
            client_secret: this.#config.clientSecret,
            code_verifier: codeVerifier
        } )

        const response = await fetch( this.#endpoints.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: tokenParams.toString()
        } )

        if( !response.ok ) {
            const errorData = await response.json().catch( () => ( {} ) )
            return {
                success: false,
                error: errorData.error || 'Authorization code exchange failed',
                errorDescription: errorData.error_description
            }
        }

        const tokens = await response.json()

        return {
            success: true,
            tokens
        }
    }


    #generateDefaultEndpoints() {
        const { providerUrl } = this.#config

        return {
            authorizationEndpoint: `${providerUrl}/authorize`,
            tokenEndpoint: `${providerUrl}/oauth/token`,
            userInfoUrl: `${providerUrl}/userinfo`,
            jwksUrl: `${providerUrl}/.well-known/jwks.json`
        }
    }


    #generateState() {
        return PKCEGenerator.generateRandomString( 32 )
    }


    validateState( { state } ) {
        const storedState = this.#stateStorage.get( state )
        return !!storedState
    }


    clearExpiredStates() {
        const now = Date.now()
        const expiredStates = []

        this.#stateStorage.forEach( ( stateData, state ) => {
            if( now - stateData.timestamp > 600000 ) {  // 10 minutes
                expiredStates.push( state )
            }
        } )

        expiredStates.forEach( ( state ) => {
            this.#stateStorage.delete( state )
        } )

        if( expiredStates.length > 0 && !this.#silent ) {
            Logger.info( {
                silent: this.#silent,
                message: `Cleaned up ${expiredStates.length} expired OAuth states`
            } )
        }

        return { cleanedStates: expiredStates.length }
    }


    getStoredStatesCount() {
        return this.#stateStorage.size
    }


    getSupportedGrantTypes() {
        return [ 'authorization_code', 'client_credentials', 'refresh_token' ]
    }


    static isScalekitEndpoint( { url } ) {
        // Accept any valid URL for ScaleKit (custom domains supported)
        return url && typeof url === 'string' && url.startsWith( 'https://' )
    }
}

export { OAuth21ScalekitFlowHandler }