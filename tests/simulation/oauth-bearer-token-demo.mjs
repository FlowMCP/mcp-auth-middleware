import { URLSearchParams } from 'url'
import crypto from 'crypto'


class OAuthBearerTokenDemo {
    #baseUrl
    #routePath
    #silent


    constructor( { baseUrl = 'http://localhost:3001', routePath = '/scalekit-route', silent = false } ) {
        this.#baseUrl = baseUrl
        this.#routePath = routePath
        this.#silent = silent
    }


    async simulateCompleteOAuthFlow() {
        this.#log( '🚀 OAuth Bearer Token Demo - Simulating complete OAuth 2.1 flow' )
        this.#log( '📍 This demo simulates the OAuth flow and shows the bearer token' )
        this.#log( '' )

        // Step 1: Discovery (real)
        const { discoveryResult } = await this.#performDiscovery()

        // Step 2: Registration (real)
        const { registrationResult } = await this.#performRegistration()

        // Step 3: Authorization (simulated - bypass external IdP)
        const { authorizationResult } = await this.#simulateAuthorization( { discoveryResult, registrationResult } )

        // Step 4: Token Exchange (real)
        const { tokenResult } = await this.#performTokenExchange( { authorizationResult, registrationResult } )

        // Step 5: Show Bearer Token
        const { bearerTokenDemo } = this.#displayBearerToken( { tokenResult } )

        return {
            success: true,
            discoveryResult,
            registrationResult,
            authorizationResult,
            tokenResult,
            bearerTokenDemo,
            summary: this.#generateSummary( { tokenResult } )
        }
    }


    async #performDiscovery() {
        this.#log( '📋 Step 1: OAuth Discovery' )

        const discoveryUrl = `${this.#baseUrl}/.well-known/oauth-authorization-server`
        this.#log( `   🔍 Discovering: ${discoveryUrl}` )

        try {
            const response = await fetch( discoveryUrl )
            const metadata = await response.json()

            this.#log( '   ✅ Discovery SUCCESS' )
            return {
                discoveryResult: {
                    success: true,
                    metadata,
                    authorizationEndpoint: metadata.authorization_endpoint,
                    tokenEndpoint: metadata.token_endpoint
                }
            }
        } catch( error ) {
            this.#log( `   ❌ Discovery FAILED: ${error.message}` )
            throw error
        }
    }


    async #performRegistration() {
        this.#log( '📝 Step 2: Client Registration' )

        const registrationUrl = `${this.#baseUrl}${this.#routePath}/oauth/register`
        this.#log( `   📤 Registering at: ${registrationUrl}` )

        const registrationData = {
            client_name: 'OAuth-Bearer-Token-Demo',
            redirect_uris: [ `${this.#baseUrl}${this.#routePath}/auth/callback` ],
            scope: 'tools:read',
            grant_types: [ 'authorization_code' ],
            response_types: [ 'code' ]
        }

        try {
            const response = await fetch( registrationUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify( registrationData )
            } )

            const clientCredentials = await response.json()

            this.#log( '   ✅ Registration SUCCESS' )
            this.#log( `   🔑 Client ID: ${clientCredentials.client_id}` )

            return {
                registrationResult: {
                    success: true,
                    clientCredentials,
                    clientId: clientCredentials.client_id,
                    clientSecret: clientCredentials.client_secret
                }
            }
        } catch( error ) {
            this.#log( `   ❌ Registration FAILED: ${error.message}` )
            throw error
        }
    }


    async #simulateAuthorization( { discoveryResult, registrationResult } ) {
        this.#log( '🔐 Step 3: Authorization (Simulated - Bypass External IdP)' )

        const { clientCredentials } = registrationResult
        const { authorizationEndpoint } = discoveryResult

        // Generate real PKCE values
        const codeVerifier = this.#generateCodeVerifier()
        const codeChallenge = await this.#generateCodeChallenge( { codeVerifier } )
        const state = this.#generateState()

        // Generate simulated authorization code (what would come from IdP)
        const simulatedAuthCode = this.#generateAuthorizationCode()

        this.#log( `   🎯 Authorization Endpoint: ${authorizationEndpoint}` )
        this.#log( `   🔑 PKCE Code Verifier: ${codeVerifier.substring( 0, 20 )}...` )
        this.#log( `   🔑 PKCE Code Challenge: ${codeChallenge.substring( 0, 20 )}...` )
        this.#log( `   🔑 State: ${state}` )
        this.#log( `   📋 Simulated Auth Code: ${simulatedAuthCode}` )
        this.#log( '   ✅ Authorization SIMULATED (External IdP bypassed)' )

        return {
            authorizationResult: {
                success: true,
                authorizationCode: simulatedAuthCode,
                state,
                codeVerifier,
                codeChallenge,
                clientId: clientCredentials.client_id,
                redirectUri: `${this.#baseUrl}${this.#routePath}/auth/callback`
            }
        }
    }


    async #performTokenExchange( { authorizationResult, registrationResult } ) {
        this.#log( '🎟️  Step 4: Token Exchange (Real)' )

        const { clientCredentials } = registrationResult
        const { authorizationCode, codeVerifier, redirectUri } = authorizationResult

        const tokenUrl = `${this.#baseUrl}${this.#routePath}/oauth/token`
        this.#log( `   📤 Token exchange at: ${tokenUrl}` )

        const tokenData = {
            grant_type: 'authorization_code',
            code: authorizationCode,
            client_id: clientCredentials.client_id,
            client_secret: clientCredentials.client_secret,
            redirect_uri: redirectUri,
            code_verifier: codeVerifier
        }

        try {
            const response = await fetch( tokenUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams( tokenData ).toString()
            } )

            const tokenResponse = await response.json()

            if( tokenResponse.access_token ) {
                this.#log( '   ✅ Token Exchange SUCCESS' )
                this.#log( `   🎯 Access Token Received: ${tokenResponse.access_token.substring( 0, 50 )}...` )

                return {
                    tokenResult: {
                        success: true,
                        accessToken: tokenResponse.access_token,
                        tokenType: tokenResponse.token_type || 'Bearer',
                        expiresIn: tokenResponse.expires_in,
                        refreshToken: tokenResponse.refresh_token,
                        scope: tokenResponse.scope,
                        fullResponse: tokenResponse
                    }
                }
            } else {
                throw new Error( `Token exchange failed: ${JSON.stringify( tokenResponse )}` )
            }

        } catch( error ) {
            this.#log( `   ❌ Token Exchange FAILED: ${error.message}` )
            throw error
        }
    }


    #displayBearerToken( { tokenResult } ) {
        this.#log( '' )
        this.#log( '🏆 BEARER TOKEN DEMONSTRATION' )
        this.#log( '═══════════════════════════════════════' )
        this.#log( '' )

        const { accessToken, tokenType, expiresIn, scope } = tokenResult

        this.#log( `📋 Token Type: ${tokenType}` )
        this.#log( `🔑 Access Token: ${accessToken}` )
        this.#log( `⏰ Expires In: ${expiresIn} seconds` )
        this.#log( `🎯 Scope: ${scope || 'tools:read'}` )
        this.#log( '' )
        this.#log( '💡 Usage Example:' )
        this.#log( `   Authorization: ${tokenType} ${accessToken}` )
        this.#log( '' )
        this.#log( '🎯 API Call Example:' )
        this.#log( `   curl -H "Authorization: ${tokenType} ${accessToken}" \\` )
        this.#log( `        ${this.#baseUrl}${this.#routePath}/sse` )
        this.#log( '' )
        this.#log( '✅ BEARER TOKEN SUCCESSFULLY DEMONSTRATED!' )

        return {
            bearerTokenDemo: {
                fullToken: `${tokenType} ${accessToken}`,
                tokenType,
                accessToken,
                expiresIn,
                scope,
                apiUsageExample: `Authorization: ${tokenType} ${accessToken}`,
                curlExample: `curl -H "Authorization: ${tokenType} ${accessToken}" ${this.#baseUrl}${this.#routePath}/sse`
            }
        }
    }


    #generateSummary( { tokenResult } ) {
        const { accessToken, tokenType } = tokenResult

        return {
            demonstration: 'Bearer Token OAuth 2.1 Flow',
            status: 'SUCCESS',
            tokenGenerated: true,
            tokenType,
            tokenLength: accessToken.length,
            tokenPreview: `${accessToken.substring( 0, 20 )}...`,
            fullBearerToken: `${tokenType} ${accessToken}`,
            conclusion: 'OAuth 2.1 flow completed successfully with bearer token generation'
        }
    }


    #generateCodeVerifier() {
        const array = new Uint8Array( 32 )
        crypto.getRandomValues( array )
        return Buffer.from( array ).toString( 'base64url' )
    }


    async #generateCodeChallenge( { codeVerifier } ) {
        const encoder = new TextEncoder()
        const data = encoder.encode( codeVerifier )
        const digest = await crypto.subtle.digest( 'SHA-256', data )
        return Buffer.from( digest ).toString( 'base64url' )
    }


    #generateState() {
        const array = new Uint8Array( 16 )
        crypto.getRandomValues( array )
        return Buffer.from( array ).toString( 'base64url' )
    }


    #generateAuthorizationCode() {
        const array = new Uint8Array( 24 )
        crypto.getRandomValues( array )
        return Buffer.from( array ).toString( 'base64url' )
    }


    #log( message ) {
        if( !this.#silent ) {
            console.log( message )
        }
    }


    static async demonstrateBearerToken( { baseUrl, routePath, silent } = {} ) {
        const demo = new OAuthBearerTokenDemo( { baseUrl, routePath, silent } )
        return await demo.simulateCompleteOAuthFlow()
    }
}


export { OAuthBearerTokenDemo }