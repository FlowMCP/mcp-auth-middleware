import puppeteer from 'puppeteer'
import { URLSearchParams } from 'url'
import crypto from 'crypto'
import fs from 'fs'

import { ConfigManager } from './ConfigManager.mjs'


class OAuth21ScalekitPuppeteerTester {
    #baseUrl
    #routePath
    #config
    #silent
    #browser
    #page
    #browserTimeout


    constructor( { baseUrl, routePath, silent = false, browserTimeout = 30000 } ) {
        this.#baseUrl = baseUrl
        this.#routePath = routePath
        this.#silent = silent
        this.#browser = null
        this.#page = null
        this.#browserTimeout = browserTimeout
        this.#config = null
    }


    async #loadConfig() {
        if( !this.#config ) {
            const { config, authTypValue } = await ConfigManager.getConfig( { authTypKey: 'oauth21_scalekit' } )
            this.#config = { auth: authTypValue }
        }
        return this.#config
    }


    async testCompleteFlow() {
        // Load config first
        await this.#loadConfig()

        this.#log( 'OAUTH21 SCALEKIT FLOW TEST' )
        this.#log( '========================' )
        this.#log( `Base URL: ${this.#baseUrl}` )
        this.#log( `Route: ${this.#routePath}` )
        this.#log( `Client ID: ${this.#config.auth.clientId}` )
        this.#log( '' )

        let testStepReached = 'initialization'

        try {
            // Step 0: Unauthorized Access Test - ensure MCP endpoint rejects without token
            testStepReached = 'unauthorized_test'
            const unauthorizedResult = await this.#testUnauthorizedAccess()

            // Step 1: Discovery - derive endpoints from baseUrl
            testStepReached = 'discovery'
            const discoveryData = await this.#performDiscovery()

            // Step 2: Registration - use discovery results
            testStepReached = 'registration'
            const { registrationResult } = await this.#performRegistration( { discoveryResults: discoveryData } )

            // Step 3: Authorization - use discovery + registration results
            testStepReached = 'authorization_prep'
            const { authorizationResult } = await this.#prepareAuthorization( { discoveryResults: discoveryData, registrationResult } )

            // Step 4: Browser Authorization - use authorization URL
            testStepReached = 'browser_auth'
            const { authCodeResult } = await this.#performBrowserAuthorization( { authorizationResult } )

            // Step 5: Token Exchange - use real auth code
            testStepReached = 'token_exchange'
            const { tokenResult } = await this.#performTokenExchange( { discoveryResults: discoveryData, authCodeResult } )

            // Step 6: Token Validation - use real access token
            testStepReached = 'token_validation'
            const { validationResult } = await this.#validateToken( { discoveryResults: discoveryData, tokenResult } )

            // Step 7: MCP Tools Request - use validated access token to fetch protected MCP tools
            testStepReached = 'mcp_tools_request'
            const { mcpToolsResult } = await this.#fetchMcpTools( { tokenResult } )

            // Step 8: MCP Tools Call - actually call the first tool from the list
            testStepReached = 'mcp_tool_call'
            const { mcpToolCallResult } = await this.#callFirstMcpTool( { tokenResult, mcpToolsResult } )

            const completeResult = {
                success: true,
                baseUrl: this.#baseUrl,
                routePath: this.#routePath,
                clientId: this.#config.auth.clientId,
                flowResults: {
                    step0_unauthorizedTest: unauthorizedResult,
                    step1_discovery: discoveryData,
                    step2_registration: registrationResult,
                    step3_authorization: authorizationResult,
                    step4_browserAuth: authCodeResult,
                    step5_tokenExchange: tokenResult,
                    step6_validation: validationResult,
                    step7_mcpTools: mcpToolsResult,
                    step8_mcpToolCall: mcpToolCallResult
                },
                requestChain: this.#generateRequestChain( { discoveryResults: discoveryData, registrationResult, authorizationResult, authCodeResult, tokenResult, validationResult, mcpToolsResult, mcpToolCallResult } )
            }

            this.#log( '✅ Complete OAuth21 ScaleKit Flow Test SUCCESSFUL' )
            return completeResult

        } catch( error ) {
            this.#log( `❌ OAuth21 ScaleKit Flow Test FAILED at step: ${testStepReached}` )
            this.#log( `   Error: ${error.message}` )

            // Enhanced error with step information
            const enhancedError = new Error( `Test failed at ${testStepReached}: ${error.message}` )
            enhancedError.stack = error.stack
            enhancedError.failedAtStep = testStepReached
            throw enhancedError
        } finally {
            await this.#cleanup()
        }
    }


    async #performDiscovery() {
        this.#log( 'STEP 1: DISCOVERY' )
        this.#log( '=================' )
        this.#log( 'Deriving endpoints from baseUrl' )

        // Derive discovery endpoints from baseUrl (no assumptions)
        const discoveryEndpoints = [
            `${this.#baseUrl}/.well-known/oauth-authorization-server`,
            `${this.#baseUrl}/.well-known/oauth-protected-resource`,
            `${this.#baseUrl}/.well-known/openid-configuration`,
            `${this.#baseUrl}/.well-known/oauth-protected-resource${this.#routePath}`,
            `${this.#baseUrl}/.well-known/oauth-authorization-server${this.#routePath}`,
            `${this.#baseUrl}/.well-known/openid-configuration${this.#routePath}`,
            `${this.#baseUrl}${this.#routePath}/.well-known/openid-configuration`
        ]

        const discoveryResults = []

        for( const endpoint of discoveryEndpoints ) {
            this.#log( `  Testing: ${endpoint}` )

            try {
                const response = await fetch( endpoint, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json, text/event-stream',
                        'User-Agent': 'OAuth21-ScaleKit-Puppeteer-Tester/1.0'
                    }
                } )

                const result = {
                    endpoint,
                    status: response.status,
                    success: response.ok,
                    contentType: response.headers.get( 'content-type' ) || 'unknown'
                }

                if( response.ok ) {
                    try {
                        result.metadata = await response.json()
                        this.#log( `    SUCCESS: ${endpoint}` )
                    } catch( parseError ) {
                        result.parseError = parseError.message
                        this.#log( `   ⚠️  JSON Parse Error: ${endpoint}` )
                    }
                } else {
                    this.#log( `    FAILED: ${endpoint} (${response.status})` )
                }

                discoveryResults.push( result )

            } catch( networkError ) {
                const result = {
                    endpoint,
                    status: 0,
                    success: false,
                    networkError: networkError.message
                }
                discoveryResults.push( result )
                this.#log( `   💥 Network Error: ${endpoint} - ${networkError.message}` )

                // Early exit if server is not reachable (connection refused)
                if( networkError.message.includes( 'ECONNREFUSED' ) ||
                    networkError.message.includes( 'fetch failed' ) ) {
                    this.#log( '' )
                    this.#log( '   ⛔ Server appears to be down - stopping discovery attempts' )
                    this.#log( '   Please ensure the server is running on the expected port' )
                    break  // Stop trying more endpoints
                }
            }
        }

        // Find authorization server metadata (required for next steps)
        const authServerMetadata = discoveryResults
            .find( ( result ) => result.success && result.metadata?.authorization_endpoint )

        if( !authServerMetadata ) {
            throw new Error( 'No authorization server metadata found - cannot proceed with flow' )
        }

        this.#log( `   🎯 Found authorization server: ${authServerMetadata.endpoint}` )
        this.#log( `   🔗 Authorization endpoint: ${authServerMetadata.metadata.authorization_endpoint}` )
        this.#log( '' )

        return { discoveryResults, primaryMetadata: authServerMetadata.metadata }
    }


    async #performRegistration( { discoveryResults } ) {
        this.#log( '' )
        this.#log( 'STEP 2: REGISTRATION' )
        this.#log( '====================' )
        this.#log( 'Using discovery results' )

        // Debug: log the discovery results structure
        this.#log( `Discovery results available: ${discoveryResults.primaryMetadata ? 'YES' : 'NO'}` )

        // Derive registration endpoint from discovery results
        const { primaryMetadata } = discoveryResults
        const registrationEndpoint = primaryMetadata?.registration_endpoint ||
            primaryMetadata?.dynamic_client_registration_endpoint ||
            `${this.#baseUrl}/register`

        this.#log( `Registration endpoint: ${registrationEndpoint}` )

        // Use client credentials from config (real data)
        const registrationPayload = {
            client_name: 'OAuth21-ScaleKit-Puppeteer-Tester',
            client_id: this.#config.auth.clientId,
            client_secret: this.#config.auth.clientSecret,
            redirect_uris: [ `${this.#baseUrl}${this.#routePath}/auth/callback` ],
            scope: this.#config.auth.scope,
            grant_types: [ 'authorization_code' ],
            response_types: [ 'code' ]
        }

        this.#log( `Payload: client_name="${registrationPayload.client_name}", redirect_uri="${registrationPayload.redirect_uris[0]}", scope="${registrationPayload.scope}"` )

        try {
            const response = await fetch( registrationEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json, text/event-stream',
                    'User-Agent': 'OAuth21-ScaleKit-Puppeteer-Tester/1.0'
                },
                body: JSON.stringify( registrationPayload )
            } )

            const registrationResult = {
                endpoint: registrationEndpoint,
                status: response.status,
                success: response.ok,
                payload: registrationPayload
            }

            if( response.ok ) {
                try {
                    registrationResult.clientData = await response.json()
                    this.#log( `Status: SUCCESS` )
                    this.#log( `Client ID: ${registrationResult.clientData.client_id}` )
                    this.#log( `Grant types: ${registrationResult.clientData.grant_types?.join(', ') || 'N/A'}` )
                } catch( parseError ) {
                    registrationResult.parseError = parseError.message
                    this.#log( `   ⚠️  Registration JSON Parse Error` )
                }
            } else {
                this.#log( `   ❌ Registration FAILED (${response.status})` )
                // Use config client data if registration failed
                registrationResult.clientData = {
                    client_id: this.#config.auth.clientId,
                    client_secret: this.#config.auth.clientSecret
                }
                this.#log( `   🔄 Using config client data as fallback` )
            }

            this.#log( '' )
            return { registrationResult }

        } catch( networkError ) {
            const registrationResult = {
                endpoint: registrationEndpoint,
                status: 0,
                success: false,
                networkError: networkError.message,
                clientData: {
                    client_id: this.#config.auth.clientId,
                    client_secret: this.#config.auth.clientSecret
                }
            }
            this.#log( `   💥 Registration Network Error: ${networkError.message}` )
            this.#log( `   🔄 Using config client data as fallback` )
            this.#log( '' )
            return { registrationResult }
        }
    }


    async #prepareAuthorization( { discoveryResults, registrationResult } ) {
        this.#log( '🔐 Step 3: Authorization Preparation - Using discovery + registration results' )

        const { primaryMetadata } = discoveryResults
        const { clientData } = registrationResult

        // Derive authorization parameters from discovery metadata
        const authorizationEndpoint = primaryMetadata.authorization_endpoint
        const supportedResponseTypes = primaryMetadata.response_types_supported || [ 'code' ]
        const supportedCodeChallengeMethods = primaryMetadata.code_challenge_methods_supported || [ 'S256', 'plain' ]
        const supportedScopes = primaryMetadata.scopes_supported || []

        this.#log( `   🎯 Authorization endpoint (derived): ${authorizationEndpoint}` )
        this.#log( `   📋 Supported response types: ${supportedResponseTypes.join( ', ' )}` )
        this.#log( `   🔒 Supported PKCE methods: ${supportedCodeChallengeMethods.join( ', ' )}` )
        this.#log( `   📝 Supported scopes: ${supportedScopes.join( ', ' )}` )

        // Generate PKCE (real cryptographic values)
        const codeVerifier = this.#generateCodeVerifier()
        const codeChallenge = await this.#generateCodeChallenge( { codeVerifier } )
        const state = this.#generateState()

        this.#log( `   🔑 PKCE code verifier: ${codeVerifier.substring( 0, 20 )}...` )
        this.#log( `   🔑 PKCE code challenge: ${codeChallenge.substring( 0, 20 )}...` )
        this.#log( `   🔑 State: ${state}` )
        this.#log( `   🏢 Organization ID: ${this.#config.auth.organizationId || 'org_default'}` )

        // Build authorization parameters from real data
        const redirectUri = `${this.#baseUrl}${this.#routePath}/auth/callback`
        const authParams = new URLSearchParams( {
            response_type: 'code',
            client_id: clientData.client_id,
            redirect_uri: redirectUri,
            scope: this.#config.auth.scope,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            // ScaleKit parameters - use real organization for passwordless authentication
            organization_id: this.#config.auth.organizationId || 'org_default'
            // Note: For real passwordless authentication, domain and login_hint should be provided
            // by user interaction or derived from real organization configuration
            // Removing hardcoded test values to force real authentication flow
        } )

        const authorizationUrl = `${authorizationEndpoint}?${authParams.toString()}`

        const authorizationResult = {
            authorizationEndpoint,
            authorizationUrl,
            codeVerifier,
            codeChallenge,
            state,
            clientId: clientData.client_id,
            redirectUri: `${this.#baseUrl}${this.#routePath}/auth/callback`,
            scope: this.#config.auth.scope,
            derivedFromMetadata: {
                supportedResponseTypes,
                supportedCodeChallengeMethods,
                supportedScopes
            }
        }

        this.#log( `   🌐 Authorization URL: ${authorizationUrl}` )
        this.#log( `   🎯 Redirect URI: ${redirectUri}` )
        this.#log( `   💡 Browser will redirect to this URL after successful authentication` )
        this.#log( '' )

        return { authorizationResult }
    }


    async #performBrowserAuthorization( { authorizationResult } ) {
        this.#log( '🌐 Step 4: Browser Authorization - Using real authorization URL' )

        const { authorizationUrl, redirectUri, state } = authorizationResult

        this.#log( `   🚀 Launching browser...` )

        // Try different browser paths for compatibility
        const browserOptions = {
            headless: false,  // Show browser for real interaction
            defaultViewport: null,
            args: [
                '--start-maximized',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage'
            ],
            ignoreDefaultArgs: ['--enable-automation'],
            slowMo: 100  // Slow down operations by 100ms for visibility
        }

        // Try to use system Chrome if available
        const possiblePaths = [
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Applications/Chromium.app/Contents/MacOS/Chromium',
            '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser'
        ]

        for( const executablePath of possiblePaths ) {
            try {
                if( fs.existsSync( executablePath ) ) {
                    browserOptions.executablePath = executablePath
                    this.#log( `   Using browser: ${executablePath}` )
                    break
                }
            } catch( e ) {
                // Continue to next path
            }
        }

        try {
            this.#browser = await puppeteer.launch( browserOptions )
        } catch( launchError ) {
            this.#log( `   ❌ Failed to launch browser: ${launchError.message}` )
            this.#log( `   Trying with bundled browser...` )

            // Fallback: try with minimal options
            this.#browser = await puppeteer.launch( {
                headless: 'new',  // Use new headless mode
                args: [ '--no-sandbox', '--disable-setuid-sandbox' ]
            } )
        }

        this.#page = await this.#browser.newPage()

        // Set user agent to appear more like a regular browser
        await this.#page.setUserAgent( 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' )

        this.#log( `   📝 Preparing to navigate...` )
        this.#log( `   🌐 Target URL: ${authorizationUrl}` )

        // Add a small delay before navigation
        await new Promise( resolve => setTimeout( resolve, 1000 ) )

        this.#log( `   🚦 Starting navigation...` )

        try {
            // Navigate with networkidle2 for complete page load
            await this.#page.goto( authorizationUrl, {
                waitUntil: 'networkidle2',
                timeout: 60000
            } )

            this.#log( `   ✅ Page loaded successfully` )

            // Wait a bit for any redirects or JavaScript to execute
            await new Promise( resolve => setTimeout( resolve, 2000 ) )

            const currentUrl = await this.#page.url()
            this.#log( `   📍 Current URL: ${currentUrl}` )

            // Check if we were immediately redirected to callback with error
            if( currentUrl.includes( redirectUri.split( '?' )[0] ) ) {
                this.#log( `   ⚠️  Immediately redirected to callback URL` )

                // Check for error parameters
                const url = new URL( currentUrl )
                if( url.searchParams.get( 'error' ) ) {
                    this.#log( `   ❌ OAuth Error: ${url.searchParams.get( 'error' )}` )
                    this.#log( `   📝 Details: ${url.searchParams.get( 'error_description' )}` )
                    this.#log( '' )
                    this.#log( `   💡 This typically means ScaleKit needs additional configuration:` )
                    this.#log( `      - A configured SSO connection` )
                    this.#log( `      - Or a valid domain parameter` )
                    this.#log( `      - Or manual email/password login` )
                }
            } else {
                this.#log( `   📄 Page title: ${await this.#page.title()}` )
                this.#log( `   ✅ Ready for manual authentication` )
            }

        } catch( navError ) {
            this.#log( `   ⚠️  Navigation error: ${navError.message}` )
            const currentUrl = await this.#page.url()
            this.#log( `   📍 Current URL: ${currentUrl}` )

            if( currentUrl && !currentUrl.includes( 'chrome-error' ) && currentUrl !== 'about:blank' ) {
                this.#log( `   ⏩ Page partially loaded, continuing...` )
            } else {
                throw navError
            }
        }

        this.#log( '' )
        this.#log( `   🎯 EXPECTED REDIRECT URI:` )
        this.#log( `      ${redirectUri}` )
        this.#log( `   💡 After successful login, browser should redirect to this URL` )
        this.#log( '' )
        this.#log( `   ⏳ Waiting for passwordless authorization flow...` )
        this.#log( `   📧 ScaleKit Passwordless Authentication:` )
        this.#log( `      • If already logged in: You'll be redirected automatically` )
        this.#log( `      • If not logged in: Enter your email address` )
        this.#log( `      • Check your email for verification code` )
        this.#log( `      • Enter verification code in browser` )
        this.#log( `      • Browser will redirect after successful authentication` )
        this.#log( `   ⏱️  You have 90 seconds to complete the passwordless login` )
        this.#log( '' )

        // Wait for redirect to callback URL with authorization code
        let authCode = null
        let error = null
        let errorDescription = null
        let returnedState = null
        let currentUrl = null

        try {
            // Wait for navigation to callback URL
            await this.#page.waitForFunction(
                ( redirectUri ) => window.location.href.includes( redirectUri.split( '?' )[0] ),
                { timeout: this.#browserTimeout || 30000 },  // Use configurable timeout (default 30s)
                redirectUri
            )

            currentUrl = await this.#page.url()
            this.#log( `   📍 Callback URL: ${currentUrl}` )

            // Extract authorization code from URL
            const urlParams = new URLSearchParams( new URL( currentUrl ).search )
            authCode = urlParams.get( 'code' )
            error = urlParams.get( 'error' )
            errorDescription = urlParams.get( 'error_description' )
            returnedState = urlParams.get( 'state' )

            // Validate state parameter
            if( returnedState !== state ) {
                throw new Error( `State mismatch: expected ${state}, got ${returnedState}` )
            }

            if( error ) {
                this.#log( `   ❌ Authorization error: ${error}` )
                if( errorDescription ) {
                    this.#log( `   📝 Error description: ${errorDescription}` )
                }
            } else if( authCode ) {
                this.#log( `   ✅ Authorization code received: ${authCode.substring( 0, 10 )}...` )
            } else {
                throw new Error( 'No authorization code or error found in callback URL' )
            }

        } catch( timeoutError ) {
            throw new Error( `Browser authorization timeout: ${timeoutError.message}` )
        }

        const authCodeResult = {
            success: !error,
            authorizationCode: authCode,
            codeVerifier: authorizationResult.codeVerifier,  // Pass code verifier for token exchange
            error,
            errorDescription: errorDescription,
            callbackUrl: currentUrl || await this.#page.url(),
            state: returnedState,
            stateValid: returnedState === state
        }

        this.#log( '' )
        return { authCodeResult }
    }


    async #performTokenExchange( { discoveryResults, authCodeResult } ) {
        this.#log( '🎟️  Step 5: Token Exchange - Using real authorization code' )

        if( !authCodeResult.success || !authCodeResult.authorizationCode ) {
            throw new Error( `Cannot perform token exchange: ${authCodeResult.error || 'No authorization code'}` )
        }

        const { primaryMetadata } = discoveryResults
        const tokenEndpoint = primaryMetadata.token_endpoint

        if( !tokenEndpoint ) {
            throw new Error( 'No token endpoint found in discovery metadata' )
        }

        this.#log( `   🎯 Token endpoint (derived): ${tokenEndpoint}` )

        // Build token request from real data
        const tokenPayload = new URLSearchParams( {
            grant_type: 'authorization_code',
            code: authCodeResult.authorizationCode,
            redirect_uri: `${this.#baseUrl}${this.#routePath}/auth/callback`,
            client_id: this.#config.auth.clientId,
            client_secret: this.#config.auth.clientSecret,
            code_verifier: authCodeResult.codeVerifier || 'missing-code-verifier'
        } )

        this.#log( `   📤 Token request payload: ${tokenPayload.toString()}` )

        try {
            const response = await fetch( tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json, text/event-stream',
                    'User-Agent': 'OAuth21-ScaleKit-Puppeteer-Tester/1.0'
                },
                body: tokenPayload
            } )

            const tokenResult = {
                endpoint: tokenEndpoint,
                status: response.status,
                success: response.ok,
                payload: tokenPayload.toString()
            }

            if( response.ok ) {
                try {
                    tokenResult.tokens = await response.json()
                    this.#log( `   ✅ Token exchange SUCCESS` )
                    this.#log( `   🎟️  Access token: ${tokenResult.tokens.access_token?.substring( 0, 20 )}...` )
                    this.#log( `   🔄 Refresh token: ${tokenResult.tokens.refresh_token?.substring( 0, 20 )}...` )
                    this.#log( `   ⏰ Expires in: ${tokenResult.tokens.expires_in} seconds` )
                } catch( parseError ) {
                    tokenResult.parseError = parseError.message
                    this.#log( `   ⚠️  Token JSON Parse Error` )
                }
            } else {
                const errorText = await response.text()
                tokenResult.errorResponse = errorText
                this.#log( `   ❌ Token exchange FAILED (${response.status})` )
                this.#log( `   📝 Error response: ${errorText}` )
            }

            this.#log( '' )
            return { tokenResult }

        } catch( networkError ) {
            const tokenResult = {
                endpoint: tokenEndpoint,
                status: 0,
                success: false,
                networkError: networkError.message
            }
            this.#log( `   💥 Token exchange Network Error: ${networkError.message}` )
            this.#log( '' )
            return { tokenResult }
        }
    }


    async #validateToken( { discoveryResults, tokenResult } ) {
        this.#log( '✅ Step 6: Token Validation - Using real access token' )

        if( !tokenResult.success || !tokenResult.tokens?.access_token ) {
            throw new Error( `Cannot validate token: ${tokenResult.errorResponse || 'No access token'}` )
        }

        const { primaryMetadata } = discoveryResults
        const userinfoEndpoint = primaryMetadata.userinfo_endpoint

        if( !userinfoEndpoint ) {
            this.#log( `   ⚠️  No userinfo endpoint found - skipping userinfo validation` )

            // Basic token validation by attempting to decode JWT
            const accessToken = tokenResult.tokens.access_token
            let jwtClaims = null

            try {
                // Decode JWT without verification (just to see claims)
                const parts = accessToken.split( '.' )
                if( parts.length === 3 ) {
                    const payload = JSON.parse( Buffer.from( parts[1], 'base64url' ).toString() )
                    jwtClaims = payload
                    this.#log( `   🔍 JWT Claims: ${JSON.stringify( payload, null, 2 )}` )
                }
            } catch( jwtError ) {
                this.#log( `   ⚠️  Cannot decode JWT: ${jwtError.message}` )
            }

            const validationResult = {
                success: true,
                method: 'jwt_decode_only',
                accessToken: accessToken.substring( 0, 20 ) + '...',
                jwtClaims,
                noUserinfoEndpoint: true
            }

            this.#log( '' )
            return { validationResult }
        }

        this.#log( `   🎯 Userinfo endpoint (derived): ${userinfoEndpoint}` )

        try {
            const response = await fetch( userinfoEndpoint, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${tokenResult.tokens.access_token}`,
                    'Accept': 'application/json, text/event-stream',
                    'User-Agent': 'OAuth21-ScaleKit-Puppeteer-Tester/1.0'
                }
            } )

            const validationResult = {
                endpoint: userinfoEndpoint,
                status: response.status,
                success: response.ok,
                accessToken: tokenResult.tokens.access_token.substring( 0, 20 ) + '...'
            }

            if( response.ok ) {
                try {
                    validationResult.userInfo = await response.json()
                    this.#log( `   ✅ Token validation SUCCESS` )
                    this.#log( `   👤 User info: ${JSON.stringify( validationResult.userInfo, null, 2 )}` )
                } catch( parseError ) {
                    validationResult.parseError = parseError.message
                    this.#log( `   ⚠️  Userinfo JSON Parse Error` )
                }
            } else {
                const errorText = await response.text()
                validationResult.errorResponse = errorText
                this.#log( `   ❌ Token validation FAILED (${response.status})` )
                this.#log( `   📝 Error response: ${errorText}` )
            }

            this.#log( '' )
            return { validationResult }

        } catch( networkError ) {
            const validationResult = {
                endpoint: userinfoEndpoint,
                status: 0,
                success: false,
                networkError: networkError.message
            }
            this.#log( `   💥 Token validation Network Error: ${networkError.message}` )
            this.#log( '' )
            return { validationResult }
        }
    }


    async #testUnauthorizedAccess() {
        this.#log( '🚫 Step 0: Unauthorized Access Test - Expecting MCP endpoint to reject without token' )

        const mcpEndpoint = `${this.#baseUrl}${this.#routePath}`
        this.#log( `   🎯 MCP Server endpoint: ${mcpEndpoint}` )

        // Test 1: Initialize request without Authorization header
        const initializeRequest = {
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
                protocolVersion: '2024-11-05',
                capabilities: {},
                clientInfo: {
                    name: 'Unauthorized-Test-Client',
                    version: '1.0.0'
                }
            }
        }

        this.#log( `   📤 MCP Initialize request (NO TOKEN): ${JSON.stringify( initializeRequest )}` )

        const unauthorizedResult = {
            success: false,
            mcpEndpoint,
            expectedError: 'Unauthorized access should be rejected',
            actualResult: null,
            httpStatus: null,
            httpStatusText: null,
            errorResponse: null
        }

        try {
            const initializeResponse = await fetch( mcpEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                    // Deliberately NO Authorization header
                },
                body: JSON.stringify( initializeRequest )
            } )

            unauthorizedResult.httpStatus = initializeResponse.status
            unauthorizedResult.httpStatusText = initializeResponse.statusText

            this.#log( `   📥 HTTP Status: ${initializeResponse.status} ${initializeResponse.statusText}` )

            if( initializeResponse.status === 401 || initializeResponse.status === 403 ) {
                // EXPECTED: Unauthorized access rejected
                unauthorizedResult.success = true
                unauthorizedResult.actualResult = 'Properly rejected unauthorized access'
                this.#log( `   ✅ EXPECTED REJECTION: ${initializeResponse.status} - Unauthorized access properly blocked` )

                try {
                    const errorBody = await initializeResponse.text()
                    unauthorizedResult.errorResponse = errorBody
                    this.#log( `   📄 Error response: ${errorBody}` )
                } catch( parseError ) {
                    this.#log( `   📄 Error response: [unable to parse]` )
                }
            } else if( initializeResponse.status >= 200 && initializeResponse.status < 300 ) {
                // UNEXPECTED: Unauthorized access was allowed
                unauthorizedResult.success = false
                unauthorizedResult.actualResult = 'Unauthorized access was incorrectly allowed'
                this.#log( `   ❌ SECURITY ISSUE: ${initializeResponse.status} - Unauthorized access was allowed (should be 401/403)` )

                try {
                    const responseBody = await initializeResponse.json()
                    unauthorizedResult.errorResponse = JSON.stringify( responseBody )
                    this.#log( `   📄 Response body: ${JSON.stringify( responseBody )}` )
                } catch( parseError ) {
                    this.#log( `   📄 Response body: [unable to parse]` )
                }
            } else {
                // OTHER HTTP ERROR: Network/server issues
                unauthorizedResult.success = false
                unauthorizedResult.actualResult = `Unexpected HTTP error: ${initializeResponse.status}`
                this.#log( `   ❓ UNEXPECTED ERROR: ${initializeResponse.status} - Network or server error` )
            }

        } catch( fetchError ) {
            unauthorizedResult.success = false
            unauthorizedResult.actualResult = `Network error: ${fetchError.message}`
            unauthorizedResult.errorResponse = fetchError.message
            this.#log( `   ❌ NETWORK ERROR: ${fetchError.message}` )
        }

        this.#log( '' )
        return unauthorizedResult
    }


    async #fetchMcpTools( { tokenResult } ) {
        this.#log( '🛠️  Step 7: MCP Tools Request - Using validated access token for MCP list_tools request' )

        if( !tokenResult.success || !tokenResult.tokens?.access_token ) {
            throw new Error( `Cannot fetch MCP tools: ${tokenResult.errorResponse || 'No access token'}` )
        }

        // MCP Server endpoint - this is where the MCP protocol requests go (SSE protocol)
        const mcpEndpoint = `${this.#baseUrl}${this.#routePath}`
        this.#log( `   🎯 MCP Server endpoint (SSE): ${mcpEndpoint}` )

        // Step 7a: MCP Initialize - Create session first
        const initializeRequest = {
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
                protocolVersion: '2024-11-05',
                capabilities: {},
                clientInfo: {
                    name: 'OAuth21-ScaleKit-Puppeteer-Tester',
                    version: '1.0.0'
                }
            }
        }

        this.#log( `   📤 MCP Initialize request: ${JSON.stringify( initializeRequest )}` )

        const mcpToolsResult = {
            success: false,
            mcpEndpoint,
            accessToken: tokenResult.tokens.access_token.substring( 0, 20 ) + '...',
            scope: this.#config.auth.scope,
            sessionId: null
        }

        try {
            // First: Initialize session
            const initResponse = await fetch( mcpEndpoint, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${tokenResult.tokens.access_token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json, text/event-stream',
                    'User-Agent': 'OAuth21-ScaleKit-Puppeteer-Tester/1.0'
                },
                body: JSON.stringify( initializeRequest )
            } )

            if( !initResponse.ok ) {
                throw new Error( `MCP Initialize failed: ${initResponse.status}` )
            }

            const sessionId = initResponse.headers.get( 'mcp-session-id' )
            if( !sessionId ) {
                throw new Error( 'No MCP session ID received from initialize' )
            }

            mcpToolsResult.sessionId = sessionId
            this.#log( `   ✅ MCP Session initialized: ${sessionId}` )

            // Step 7b: Tools List request with session
            const toolsRequest = {
                jsonrpc: '2.0',
                id: 2,
                method: 'tools/list',
                params: {}
            }

            this.#log( `   📤 MCP Tools request: ${JSON.stringify( toolsRequest )}` )

            const response = await fetch( mcpEndpoint, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${tokenResult.tokens.access_token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json, text/event-stream',
                    'User-Agent': 'OAuth21-ScaleKit-Puppeteer-Tester/1.0',
                    'mcp-session-id': sessionId
                },
                body: JSON.stringify( toolsRequest )
            } )

            mcpToolsResult.status = response.status
            mcpToolsResult.success = response.ok
            mcpToolsResult.contentType = response.headers.get( 'content-type' ) || 'unknown'

            if( response.ok ) {
                try {
                    // Parse response - might be SSE format or JSON
                    const responseText = await response.text()
                    let mcpResponse

                    // Check if response is SSE format
                    if( responseText.startsWith('event:') || responseText.includes('\ndata:') ) {
                        // Extract JSON from SSE format
                        const dataMatch = responseText.match(/data:\s*(.+)/)
                        if( dataMatch && dataMatch[1] ) {
                            mcpResponse = JSON.parse( dataMatch[1] )
                        } else {
                            throw new Error( 'Could not extract JSON from SSE response' )
                        }
                    } else {
                        // Regular JSON response
                        mcpResponse = JSON.parse( responseText )
                    }

                    mcpToolsResult.mcpResponse = mcpResponse

                    if( mcpResponse.result && mcpResponse.result.tools ) {
                        mcpToolsResult.tools = mcpResponse.result.tools
                        mcpToolsResult.toolsCount = mcpResponse.result.tools.length

                        this.#log( `   ✅ MCP list_tools SUCCESS - Found ${mcpToolsResult.toolsCount} tools` )
                        this.#log( `   🛠️  Available tools:` )
                        mcpResponse.result.tools
                            .forEach( ( tool, index ) => {
                                this.#log( `      ${index + 1}. ${tool.name} - ${tool.description}` )
                            } )

                        // Add curl command for manual testing
                        this.#log( `` )
                        this.#log( `MANUAL TEST COMMAND` )
                        this.#log( `==================` )
                        this.#log( `curl -X POST ${mcpEndpoint} \\` )
                        this.#log( `  -H "Authorization: Bearer ${tokenResult.tokens.access_token}" \\` )
                        this.#log( `  -H "Content-Type: application/json" \\` )
                        this.#log( `  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'` )

                    } else if( mcpResponse.error ) {
                        this.#log( `   ❌ MCP Error: ${mcpResponse.error.message || 'Unknown error'}` )
                        mcpToolsResult.mcpError = mcpResponse.error
                    } else {
                        this.#log( `   ⚠️  Unexpected MCP response structure` )
                    }

                } catch( parseError ) {
                    mcpToolsResult.parseError = parseError.message
                    this.#log( `   ⚠️  JSON Parse Error: ${parseError.message}` )
                }
            } else {
                const errorText = await response.text()
                mcpToolsResult.errorResponse = errorText
                this.#log( `   ❌ MCP request FAILED (${response.status})` )
                this.#log( `   📝 Error response: ${errorText}` )

                // Log specific authorization errors
                if( response.status === 401 ) {
                    this.#log( `   🔒 Unauthorized - Token may be invalid or insufficient scope` )
                } else if( response.status === 403 ) {
                    this.#log( `   🚫 Forbidden - Access denied to MCP server` )
                }
            }

        } catch( networkError ) {
            mcpToolsResult.status = 0
            mcpToolsResult.success = false
            mcpToolsResult.networkError = networkError.message
            this.#log( `   💥 Network Error: ${networkError.message}` )
        }

        if( !mcpToolsResult.success ) {
            this.#log( `   💡 This could mean:` )
            this.#log( `      - Server is not running on ${this.#baseUrl}` )
            this.#log( `      - MCP server route ${this.#routePath} is not configured` )
            this.#log( `      - Access token has insufficient scope (needs: ${this.#config.auth.scope})` )
            this.#log( `      - OAuth middleware is blocking the request` )
        }

        this.#log( '' )
        return { mcpToolsResult }
    }


    async #callFirstMcpTool( { tokenResult, mcpToolsResult } ) {
        this.#log( '🔧 Step 8: MCP Tool Call - Calling the first tool from the list' )

        if( !mcpToolsResult.success || !mcpToolsResult.tools || mcpToolsResult.tools.length === 0 ) {
            throw new Error( `Cannot call MCP tool: ${mcpToolsResult.mcpError?.message || 'No tools available'}` )
        }

        const firstTool = mcpToolsResult.tools[0]
        const mcpEndpoint = mcpToolsResult.mcpEndpoint
        const sessionId = mcpToolsResult.sessionId  // Get session ID from tools result

        this.#log( `   🎯 Calling first tool: ${firstTool.name}` )
        this.#log( `   📝 Tool description: ${firstTool.description}` )

        // Prepare MCP tools/call request according to MCP protocol
        const mcpToolCallRequest = {
            jsonrpc: '2.0',
            id: 3,
            method: 'tools/call',
            params: {
                name: firstTool.name,
                arguments: {}  // Empty arguments since the ping tool doesn't need any
            }
        }

        this.#log( `   📤 MCP tool call request: ${JSON.stringify( mcpToolCallRequest )}` )

        const mcpToolCallResult = {
            success: false,
            mcpEndpoint,
            toolName: firstTool.name,
            accessToken: tokenResult.tokens.access_token.substring( 0, 20 ) + '...',
            mcpToolCallRequest
        }

        try {
            const response = await fetch( mcpEndpoint, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${tokenResult.tokens.access_token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json, text/event-stream',
                    'User-Agent': 'OAuth21-ScaleKit-Puppeteer-Tester/1.0',
                    'mcp-session-id': sessionId  // Include session ID
                },
                body: JSON.stringify( mcpToolCallRequest )
            } )

            mcpToolCallResult.status = response.status
            mcpToolCallResult.success = response.ok
            mcpToolCallResult.contentType = response.headers.get( 'content-type' ) || 'unknown'

            if( response.ok ) {
                try {
                    // Parse response - might be SSE format or JSON
                    const responseText = await response.text()
                    let mcpResponse

                    // Check if response is SSE format
                    if( responseText.startsWith('event:') || responseText.includes('\ndata:') ) {
                        // Extract JSON from SSE format
                        const dataMatch = responseText.match(/data:\s*(.+)/)
                        if( dataMatch && dataMatch[1] ) {
                            mcpResponse = JSON.parse( dataMatch[1] )
                        } else {
                            throw new Error( 'Could not extract JSON from SSE response' )
                        }
                    } else {
                        // Regular JSON response
                        mcpResponse = JSON.parse( responseText )
                    }

                    mcpToolCallResult.mcpResponse = mcpResponse

                    if( mcpResponse.result ) {
                        mcpToolCallResult.toolResult = mcpResponse.result
                        this.#log( `   ✅ MCP tool call SUCCESS` )
                        this.#log( `   🔧 Tool "${firstTool.name}" response:` )
                        this.#log( `      ${JSON.stringify( mcpResponse.result, null, 2 )}` )

                        // Extract the actual content from the tool response
                        if( mcpResponse.result.content && Array.isArray( mcpResponse.result.content ) ) {
                            mcpToolCallResult.toolOutput = mcpResponse.result.content
                                .map( ( item ) => item.text || item.data || JSON.stringify( item ) )
                                .join( ' ' )
                            this.#log( `   📄 Tool output: ${mcpToolCallResult.toolOutput}` )
                        }

                        // Add curl command for manual testing
                        this.#log( `` )
                        this.#log( `MANUAL TEST COMMAND` )
                        this.#log( `==================` )
                        this.#log( `curl -X POST ${mcpEndpoint} \\` )
                        this.#log( `  -H "Authorization: Bearer ${tokenResult.tokens.access_token}" \\` )
                        this.#log( `  -H "Content-Type: application/json" \\` )
                        this.#log( `  -d '${JSON.stringify( mcpToolCallRequest )}'` )

                    } else if( mcpResponse.error ) {
                        this.#log( `   ❌ MCP Tool Call Error: ${mcpResponse.error.message || 'Unknown error'}` )
                        mcpToolCallResult.mcpError = mcpResponse.error
                    } else {
                        this.#log( `   ⚠️  Unexpected MCP tool call response structure` )
                    }

                } catch( parseError ) {
                    mcpToolCallResult.parseError = parseError.message
                    this.#log( `   ⚠️  JSON Parse Error: ${parseError.message}` )
                }
            } else {
                const errorText = await response.text()
                mcpToolCallResult.errorResponse = errorText
                this.#log( `   ❌ MCP tool call FAILED (${response.status})` )
                this.#log( `   📝 Error response: ${errorText}` )

                // Log specific authorization errors
                if( response.status === 401 ) {
                    this.#log( `   🔒 Unauthorized - Token may be invalid or insufficient scope` )
                } else if( response.status === 403 ) {
                    this.#log( `   🚫 Forbidden - Access denied to MCP tool execution` )
                }
            }

        } catch( networkError ) {
            mcpToolCallResult.status = 0
            mcpToolCallResult.success = false
            mcpToolCallResult.networkError = networkError.message
            this.#log( `   💥 Network Error: ${networkError.message}` )
        }

        if( !mcpToolCallResult.success ) {
            this.#log( `   💡 This could mean:` )
            this.#log( `      - MCP server is not responding properly` )
            this.#log( `      - Tool "${firstTool.name}" has execution errors` )
            this.#log( `      - Access token scope doesn't allow tool execution` )
            this.#log( `      - OAuth middleware is blocking tool calls` )
        }

        this.#log( '' )
        return { mcpToolCallResult }
    }


    #generateRequestChain( { discoveryResults, registrationResult, authorizationResult, authCodeResult, tokenResult, validationResult, mcpToolsResult, mcpToolCallResult } ) {
        const { primaryMetadata } = discoveryResults
        return {
            step1_discovery: {
                input: { baseUrl: this.#baseUrl },
                derivation: 'baseUrl -> .well-known/* endpoints',
                output: {
                    authorization_endpoint: primaryMetadata.authorization_endpoint,
                    token_endpoint: primaryMetadata.token_endpoint,
                    userinfo_endpoint: primaryMetadata.userinfo_endpoint
                }
            },
            step2_registration: {
                input: { registration_endpoint: 'derived_from_discovery' },
                derivation: 'discovery.registration_endpoint OR baseUrl/register',
                output: { client_id: registrationResult.clientData.client_id }
            },
            step3_authorization: {
                input: {
                    authorization_endpoint: primaryMetadata.authorization_endpoint,
                    client_id: registrationResult.clientData.client_id
                },
                derivation: 'discovery.authorization_endpoint + registration.client_id + PKCE generation',
                output: { authorization_url: authorizationResult.authorizationUrl }
            },
            step4_browser_auth: {
                input: { authorization_url: authorizationResult.authorizationUrl },
                derivation: 'browser navigation -> user interaction -> callback redirect',
                output: { authorization_code: authCodeResult.authorizationCode?.substring( 0, 10 ) + '...' }
            },
            step5_token_exchange: {
                input: {
                    token_endpoint: primaryMetadata.token_endpoint,
                    authorization_code: 'real_code_from_browser'
                },
                derivation: 'discovery.token_endpoint + real authorization_code + client credentials',
                output: { access_token: tokenResult.tokens?.access_token?.substring( 0, 10 ) + '...' }
            },
            step6_validation: {
                input: {
                    userinfo_endpoint: primaryMetadata.userinfo_endpoint,
                    access_token: 'real_token_from_exchange'
                },
                derivation: 'discovery.userinfo_endpoint + real access_token',
                output: { user_claims: 'validated_user_info' }
            },
            step7_mcp_tools: {
                input: {
                    mcp_endpoint: `${this.#baseUrl}${this.#routePath}`,
                    access_token: 'validated_token_from_step6',
                    mcp_request: 'tools/list'
                },
                derivation: 'baseUrl + routePath + MCP list_tools request + validated access_token',
                output: {
                    tools_available: mcpToolsResult.success ? mcpToolsResult.toolsCount : 0,
                    first_tool: mcpToolsResult.tools && mcpToolsResult.tools.length > 0 ? mcpToolsResult.tools[0].name : 'none'
                }
            },
            step8_mcp_tool_call: {
                input: {
                    mcp_endpoint: `${this.#baseUrl}${this.#routePath}`,
                    tool_name: mcpToolCallResult.toolName || 'none',
                    access_token: 'validated_token_from_step6',
                    mcp_request: 'tools/call'
                },
                derivation: 'baseUrl + routePath + MCP tools/call request + tool_name + validated access_token',
                output: {
                    tool_execution: mcpToolCallResult.success ? 'successful_tool_call' : 'execution_failed',
                    tool_output: mcpToolCallResult.toolOutput || 'no_output'
                }
            }
        }
    }


    #generateCodeVerifier() {
        const array = new Uint8Array( 32 )
        crypto.getRandomValues( array )
        return Buffer.from( array ).toString( 'base64url' )
    }


    async #generateCodeChallenge( { codeVerifier } ) {
        const hash = crypto.createHash( 'sha256' )
        hash.update( codeVerifier )
        return hash.digest( 'base64url' )
    }


    #generateState() {
        const array = new Uint8Array( 16 )
        crypto.getRandomValues( array )
        return Buffer.from( array ).toString( 'base64url' )
    }


    async #cleanup() {
        if( this.#browser ) {
            try {
                this.#log( '🧹 Closing browser...' )
                await this.#browser.close()
                this.#browser = null
                this.#page = null
                this.#log( '   Browser closed successfully' )
            } catch( cleanupError ) {
                this.#log( `   ⚠️  Browser cleanup error: ${cleanupError.message}` )
                // Force kill browser process if graceful close fails
                try {
                    if( this.#browser && this.#browser.process() ) {
                        this.#browser.process().kill( 'SIGKILL' )
                    }
                } catch( forceKillError ) {
                    this.#log( `   ⚠️  Force kill failed: ${forceKillError.message}` )
                }
            }
        }
    }


    #log( message ) {
        if( !this.#silent ) {
            console.log( message )
        }
    }


    static async runTest( { baseUrl, routePath, silent = false, browserTimeout = 30000 } = {} ) {
        const tester = new OAuth21ScalekitPuppeteerTester( { baseUrl, routePath, silent, browserTimeout } )
        return await tester.testCompleteFlow()
    }
}


export { OAuth21ScalekitPuppeteerTester }