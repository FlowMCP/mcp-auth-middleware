import fetch from 'node-fetch'
import crypto from 'crypto'

import { PKCEGenerator } from './PKCEGenerator.mjs'


class OAuthFlowHandler {
    #config
    #silent
    #authorizationRequests


    constructor( { silent = false } ) {
        this.#silent = silent
        this.#authorizationRequests = new Map()
    }


    static create( { keycloakUrl, realm, clientId, clientSecret, redirectUri, silent = false } ) {
        const handler = new OAuthFlowHandler( { silent } )
        
        const config = {
            keycloakUrl,
            realm,
            clientId,
            clientSecret,
            redirectUri,
            authorizationEndpoint: `${keycloakUrl}/realms/${realm}/protocol/openid-connect/auth`,
            tokenEndpoint: `${keycloakUrl}/realms/${realm}/protocol/openid-connect/token`,
            deviceAuthorizationEndpoint: `${keycloakUrl}/realms/${realm}/protocol/openid-connect/auth/device`
        }
        
        handler.#config = config

        return handler
    }


    initiateAuthorizationCodeFlow( { scopes = [ 'openid' ], resourceIndicators = [] } ) {
        const state = crypto.randomBytes( 16 ).toString( 'base64url' )
        const { pair } = PKCEGenerator.generatePKCEPair()
        
        const authRequest = {
            state,
            codeVerifier: pair.codeVerifier,
            codeChallenge: pair.codeChallenge,
            codeChallengeMethod: pair.codeChallengeMethod,
            scopes,
            resourceIndicators,
            timestamp: Date.now()
        }
        
        this.#authorizationRequests.set( state, authRequest )
        
        const params = new URLSearchParams( {
            response_type: 'code',
            client_id: this.#config.clientId,
            redirect_uri: this.#config.redirectUri,
            scope: scopes.join( ' ' ),
            state,
            code_challenge: pair.codeChallenge,
            code_challenge_method: pair.codeChallengeMethod
        } )
        
        if( resourceIndicators.length > 0 ) {
            params.append( 'resource', resourceIndicators.join( ' ' ) )
        }
        
        const authorizationUrl = `${this.#config.authorizationEndpoint}?${params.toString()}`
        
        if( !this.#silent ) {
            console.log( `Authorization URL: ${authorizationUrl}` )
        }

        return { authorizationUrl, state }
    }


    async handleAuthorizationCallback( { code, state } ) {
        const authRequest = this.#authorizationRequests.get( state )
        
        if( !authRequest ) {
            return { 
                success: false, 
                error: 'Invalid state parameter' 
            }
        }
        
        const { tokens } = await this.#exchangeCodeForTokens( { 
            code, 
            codeVerifier: authRequest.codeVerifier 
        } )
        
        this.#authorizationRequests.delete( state )
        
        return { 
            success: true, 
            tokens 
        }
    }


    async requestClientCredentials( { scopes = [] } ) {
        const params = new URLSearchParams( {
            grant_type: 'client_credentials',
            client_id: this.#config.clientId,
            client_secret: this.#config.clientSecret
        } )
        
        if( scopes.length > 0 ) {
            params.append( 'scope', scopes.join( ' ' ) )
        }
        
        const response = await fetch( this.#config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params
        } )
        
        const tokens = await response.json()
        
        if( !this.#silent ) {
            console.log( 'Client credentials obtained successfully' )
        }

        return { tokens }
    }


    async refreshAccessToken( { refreshToken } ) {
        const params = new URLSearchParams( {
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: this.#config.clientId,
            client_secret: this.#config.clientSecret
        } )
        
        const response = await fetch( this.#config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params
        } )
        
        const tokens = await response.json()
        
        if( tokens.error ) {
            return { 
                success: false, 
                error: tokens.error_description || 'Token refresh failed' 
            }
        }

        return { 
            success: true, 
            tokens 
        }
    }


    async #exchangeCodeForTokens( { code, codeVerifier } ) {
        const params = new URLSearchParams( {
            grant_type: 'authorization_code',
            code,
            redirect_uri: this.#config.redirectUri,
            client_id: this.#config.clientId,
            code_verifier: codeVerifier
        } )
        
        if( this.#config.clientSecret ) {
            params.append( 'client_secret', this.#config.clientSecret )
        }
        
        const response = await fetch( this.#config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params
        } )
        
        const tokens = await response.json()

        return { tokens }
    }
}

export { OAuthFlowHandler }