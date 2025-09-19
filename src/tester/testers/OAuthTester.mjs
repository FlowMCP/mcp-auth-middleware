import puppeteer from 'puppeteer'
import crypto from 'crypto'

import { StreamableTransport } from '../helpers/StreamableTransport.mjs'
import { DiagnosticAnalyzer } from '../helpers/DiagnosticAnalyzer.mjs'


class OAuthTester {
    static async runTest( { baseUrl, routePath, oauth21Config, browserTimeout = 90000, silent = false, testUnauthorized = true, expectedUnauthorizedStatus = 401, useDynamicRegistration = false } ) {
        console.log( '\n🔍 Starting OAuth21 ScaleKit Test...' )
        console.log( '═'.repeat( 60 ) )
        console.log( `   Endpoint: ${baseUrl}${routePath}` )
        console.log( `   Method: OAuth21 ScaleKit Authentication` )

        // Handle dynamic registration mode
        if( useDynamicRegistration ) {
            console.log( `   Mode: Dynamic Client Registration (DCR)` )
            console.log( `   Provider: Will be discovered from target` )
        } else {
            console.log( `   Provider: ${oauth21Config.providerUrl}` )
            console.log( `   Client ID: ${oauth21Config.clientId}` )
        }
        console.log( '═'.repeat( 60 ) )

        const testResult = {
            success: false,
            testType: 'oauth_streamable',
            timestamp: new Date().toISOString(),
            configuration: {
                baseUrl,
                routePath,
                oauth21Config: useDynamicRegistration ? { mode: 'dynamic' } : {
                    ...oauth21Config,
                    clientSecret: `${oauth21Config.clientSecret.substring( 0, 8 )}...`
                },
                browserTimeout,
                useDynamicRegistration
            },
            naiveTest: null,
            authTest: null,
            oauthFlow: {},
            diagnostics: null,
            rawData: {}
        }

        const requestChain = []
        let browser = null

        try {
            if( testUnauthorized ) {
                console.log( '🔓 Testing unauthorized access...' )
                const naiveResponse = await StreamableTransport.sendMcpRequest( {
                    baseUrl,
                    routePath,
                    mcpMethod: 'initialize',
                    mcpParams: {
                        protocolVersion: '2024-11-05',
                        capabilities: {},
                        clientInfo: { name: 'test-client', version: '1.0.0' }
                    },
                    timeout: 30000
                } )

                requestChain.push( {
                    step: 'naive_unauthorized_test',
                    request: naiveResponse.requestDetails,
                    response: {
                        status: naiveResponse.status,
                        statusText: naiveResponse.statusText,
                        headers: naiveResponse.headers,
                        body: naiveResponse.body
                    }
                } )

                const naiveSuccess = naiveResponse.status === expectedUnauthorizedStatus || ( naiveResponse.status >= 401 && naiveResponse.status <= 403 )

                console.log( '\n🛡️  Unauthorized Access Test Result:' )
                console.log( '─'.repeat( 50 ) )
                if( naiveSuccess ) {
                    console.log( `   ✅ PROPERLY REJECTED: HTTP ${naiveResponse.status} ${naiveResponse.statusText}` )
                    console.log( `   🔒 Security Status: OAuth authentication required (Good!)` )
                } else if( naiveResponse.status < 400 ) {
                    console.log( `   ⚠️  SECURITY WARNING: HTTP ${naiveResponse.status} ${naiveResponse.statusText}` )
                    console.log( `   🔓 Security Status: Route appears publicly accessible!` )
                } else {
                    console.log( `   ❓ UNEXPECTED: HTTP ${naiveResponse.status} ${naiveResponse.statusText}` )
                    console.log( `   🔍 Expected: ${expectedUnauthorizedStatus} or 401-403 range` )
                }
                console.log( '─'.repeat( 50 ) )

                testResult.naiveTest = {
                    success: naiveSuccess,
                    httpStatus: naiveResponse.status,
                    httpStatusText: naiveResponse.statusText,
                    expectedRejection: true,
                    message: naiveSuccess ?
                        `Properly rejected unauthorized access (${naiveResponse.status})` :
                        `Unexpected response: expected ${expectedUnauthorizedStatus} or 401-403, got ${naiveResponse.status}`
                }
            }

            console.log( '\n🔍 Starting OAuth21 Flow...' )

            // If using dynamic registration, first discover provider from target
            if( useDynamicRegistration ) {
                console.log( '🔎 Step 0: Provider Discovery from Target...' )
                oauth21Config = await this.#discoverProviderFromUrl( { baseUrl, routePath, requestChain } )
                console.log( `   ✅ Discovered provider: ${oauth21Config.providerUrl}` )
                testResult.oauthFlow.providerDiscovery = oauth21Config
            }

            console.log( '🌐 Step 1: OAuth Discovery...' )
            const discoveryData = await this.#performDiscovery( { baseUrl, oauth21Config, requestChain } )
            testResult.oauthFlow.discovery = discoveryData

            console.log( '📝 Step 2: Client Registration...' )
            const registrationResult = await this.#performRegistration( {
                discoveryData,
                oauth21Config,
                baseUrl,
                requestChain,
                useDynamicRegistration
            } )
            testResult.oauthFlow.registration = registrationResult

            console.log( '🔐 Step 3: Authorization Preparation...' )
            const authorizationResult = await this.#prepareAuthorization( { discoveryData, registrationResult, oauth21Config, baseUrl, routePath, requestChain } )
            testResult.oauthFlow.authorization = authorizationResult

            console.log( '🌐 Step 4: Browser Authorization (Puppeteer)...' )
            console.log( '   ⚠️  Browser will open for manual authentication' )

            // Use the correct Puppeteer setup from OAuth21ScalekitPuppeteerTester
            const browserOptions = {
                headless: false,
                defaultViewport: null,
                args: [
                    '--start-maximized',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage'
                ],
                ignoreDefaultArgs: ['--enable-automation'],
                slowMo: 100
            }

            // Try to use system Chrome if available (this fixes the launch issue!)
            const possiblePaths = [
                '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                '/Applications/Chromium.app/Contents/MacOS/Chromium',
                '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser'
            ]

            for( const executablePath of possiblePaths ) {
                try {
                    const fs = ( await import( 'fs' ) ).default
                    if( fs.existsSync( executablePath ) ) {
                        browserOptions.executablePath = executablePath
                        console.log( `🌐 Using system browser: ${executablePath}` )
                        break
                    }
                } catch( e ) {
                    // Continue to next path
                }
            }

            console.log( '🚀 Launching browser...' )

            try {
                browser = await puppeteer.launch( browserOptions )
                console.log( '✅ Browser launched successfully (visible mode)' )
            } catch( launchError ) {
                console.log( '⚠️  Non-headless browser failed, trying new headless mode...' )
                console.log( `   Error: ${launchError.message}` )

                // Fallback: Use new headless mode
                try {
                    browser = await puppeteer.launch( {
                        headless: 'new',
                        args: [ '--no-sandbox', '--disable-setuid-sandbox' ]
                    } )
                    console.log( '✅ Browser launched successfully (headless mode)' )
                    console.log( '   Note: Browser will not be visible, but OAuth flow will work' )
                } catch( headlessError ) {
                    console.log( '❌ Failed to launch browser in any mode' )
                    throw new Error( `Puppeteer launch failed: ${headlessError.message}` )
                }
            }

            const authCodeResult = await this.#performBrowserAuthorization( { browser, authorizationResult, browserTimeout, requestChain } )
            testResult.oauthFlow.browserAuth = authCodeResult

            console.log( '🎫 Step 5: Token Exchange...' )
            const tokenResult = await this.#performTokenExchange( { discoveryData, authCodeResult, oauth21Config, authorizationResult, requestChain } )
            testResult.oauthFlow.tokenExchange = tokenResult

            console.log( '✅ Step 6: Token Validation...' )
            const validationResult = await this.#validateToken( { discoveryData, tokenResult, requestChain } )
            testResult.oauthFlow.tokenValidation = validationResult

            console.log( '🛠️  Step 7: MCP Flow with OAuth Token...' )
            const mcpResult = await this.#performMcpFlow( { baseUrl, routePath, tokenResult, requestChain } )
            testResult.authTest = mcpResult

            if( mcpResult.success ) {
                console.log( '\n✨ OAuth Test Complete!' )
                console.log( '═'.repeat( 60 ) )
                console.log( `   Status: ✅ SUCCESS` )
                console.log( `   Summary: OAuth21 ScaleKit authentication successful` )
                console.log( `   Provider: ${oauth21Config.providerUrl}` )
                console.log( `   Tools Available: ${mcpResult.toolsFound}` )
                if( mcpResult.toolTest ) {
                    console.log( `   Tool tested: ${mcpResult.toolTest.toolName} - ${mcpResult.toolTest.success ? 'SUCCESS' : 'FAILED'}` )
                    if( mcpResult.toolTest.success && mcpResult.toolTest.result ) {
                        console.log( `   Tool result: ${JSON.stringify( mcpResult.toolTest.result )}` )
                    }
                }
                console.log( '═'.repeat( 60 ) )

                testResult.success = true
                testResult.diagnostics = {
                    summary: 'OAuth21 ScaleKit authentication and MCP protocol working correctly',
                    details: {
                        authenticationMethod: 'OAuth21 ScaleKit',
                        oauthProvider: oauth21Config.providerUrl,
                        clientId: oauth21Config.clientId,
                        mcpProtocolVersion: mcpResult.mcpVersion,
                        toolsAvailable: mcpResult.toolsFound
                    }
                }
            } else {
                console.log( '\n❌ OAuth Test Failed!' )
                console.log( '═'.repeat( 60 ) )
                console.log( `   Status: ❌ FAILED` )
                console.log( `   Error: ${mcpResult.error}` )
                console.log( '═'.repeat( 60 ) )
                throw new Error( `MCP flow failed: ${mcpResult.error}` )
            }

            testResult.rawData = { requestChain, oauthFlow: testResult.oauthFlow }

        } catch( testError ) {
            const errorAnalysis = DiagnosticAnalyzer.analyzeStreamableFailure( {
                response: { error: testError.message, success: false },
                testType: 'oauth',
                step: testResult.oauthFlow.currentStep,
                context: { oauth21: true, ...oauth21Config }
            } )

            testResult.success = false
            testResult.authTest = {
                success: false,
                error: testError.message,
                step: testResult.oauthFlow.currentStep
            }

            testResult.diagnostics = DiagnosticAnalyzer.buildDiagnosticReport( {
                testType: 'oauth_streamable',
                errorDetails: errorAnalysis,
                fullContext: {
                    response: { error: testError.message },
                    requestChain,
                    testConfig: testResult.configuration,
                    oauthFlow: testResult.oauthFlow
                }
            } )

            testResult.rawData = { testError: testError.message, requestChain, oauthFlow: testResult.oauthFlow }
        } finally {
            if( browser ) {
                await browser.close()
            }
        }

        return testResult
    }


    static async #discoverProviderFromUrl( { baseUrl, routePath, requestChain } ) {
        console.log( `🔍 Attempting to discover OAuth provider from ${baseUrl}${routePath}` )

        try {
            // First try to get protected resource metadata
            const resourceMetadataUrl = `${baseUrl}/.well-known/oauth-protected-resource${routePath}`
            console.log( `📋 Checking resource metadata at: ${resourceMetadataUrl}` )

            const metadataResponse = await StreamableTransport.makeRequest( {
                baseUrl,
                routePath: `/.well-known/oauth-protected-resource${routePath}`,
                method: 'GET',
                timeout: 30000
            } )

            if( metadataResponse.success && metadataResponse.body ) {
                const metadata = metadataResponse.body
                console.log( `✅ Found resource metadata` )

                requestChain.push( {
                    step: 'provider_discovery_metadata',
                    request: metadataResponse.requestDetails,
                    response: {
                        status: metadataResponse.status,
                        statusText: metadataResponse.statusText,
                        headers: metadataResponse.headers,
                        body: metadata
                    }
                } )

                // Extract authorization servers
                const authServers = metadata.authorization_servers || []
                if( authServers.length > 0 ) {
                    const providerUrl = authServers[0]
                    console.log( `   Found authorization server: ${providerUrl}` )

                    // Extract resource and scope information
                    const resource = metadata.resource || `${baseUrl}${routePath}`
                    const scope = metadata.scopes_supported ?
                        metadata.scopes_supported.join( ' ' ) :
                        'mcp:tools:* mcp:resources:read'

                    return {
                        providerUrl: providerUrl.replace( /\/resources\/.*$/, '' ), // Extract base URL
                        resource,
                        scope,
                        organizationId: 'dynamic', // Will be replaced by DCR
                        clientId: null, // Will be set by DCR
                        clientSecret: null // Will be set by DCR
                    }
                }
            }
        } catch( error ) {
            console.log( `   ⚠️  Resource metadata not found, trying unauthorized request...` )
        }

        // Fallback: Make unauthorized request and parse WWW-Authenticate header
        const unauthorizedResponse = await StreamableTransport.makeRequest( {
            baseUrl,
            routePath,
            method: 'GET',
            timeout: 30000
        } )

        requestChain.push( {
            step: 'provider_discovery_401',
            request: unauthorizedResponse.requestDetails,
            response: {
                status: unauthorizedResponse.status,
                statusText: unauthorizedResponse.statusText,
                headers: unauthorizedResponse.headers,
                body: unauthorizedResponse.body
            }
        } )

        if( unauthorizedResponse.status === 401 ) {
            const wwwAuth = unauthorizedResponse.headers['www-authenticate']
            if( wwwAuth ) {
                console.log( `   Parsing WWW-Authenticate header: ${wwwAuth}` )

                // Parse Bearer realm and other parameters
                const realmMatch = wwwAuth.match( /realm="([^"]+)"/ )
                const resourceMatch = wwwAuth.match( /resource="([^"]+)"/ )

                if( realmMatch ) {
                    const realm = realmMatch[1]
                    console.log( `   Found realm: ${realm}` )

                    // If realm is a URL, use it as provider
                    if( realm.startsWith( 'http' ) ) {
                        return {
                            providerUrl: realm.replace( /\/resources\/.*$/, '' ),
                            resource: resourceMatch ? resourceMatch[1] : `${baseUrl}${routePath}`,
                            scope: 'mcp:tools:* mcp:resources:read',
                            organizationId: 'dynamic',
                            clientId: null,
                            clientSecret: null
                        }
                    }
                }
            }
        }

        // Smart default based on the target domain
        let defaultProvider = 'https://auth.scalekit.com'
        if( baseUrl.includes( 'flowmcp.org' ) ) {
            defaultProvider = 'https://auth.flowmcp.org'
            console.log( `   ⚠️  Could not discover provider, defaulting to FlowMCP Auth` )
        } else {
            console.log( `   ⚠️  Could not discover provider, defaulting to ScaleKit` )
        }

        return {
            providerUrl: defaultProvider,
            resource: `${baseUrl}${routePath}`,
            scope: 'mcp:tools:* mcp:resources:read',
            organizationId: 'dynamic',
            clientId: null,
            clientSecret: null
        }
    }


    static async #performDiscovery( { baseUrl, oauth21Config, requestChain } ) {
        const discoveryUrl = `${oauth21Config.providerUrl}/.well-known/openid-configuration`

        const response = await StreamableTransport.makeRequest( {
            baseUrl: oauth21Config.providerUrl,
            routePath: '/.well-known/openid-configuration',
            method: 'GET',
            timeout: 30000
        } )

        requestChain.push( {
            step: 'oauth_discovery',
            request: response.requestDetails,
            response: {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
                body: response.body
            }
        } )

        if( !response.success ) {
            throw new Error( `Discovery failed: ${response.status} ${response.statusText}` )
        }

        const discoveryData = response.body
        console.log( '📋 Discovery data endpoints found:' )
        console.log( `   authorization_endpoint: ${discoveryData.authorization_endpoint}` )
        console.log( `   token_endpoint: ${discoveryData.token_endpoint}` )
        console.log( `   userinfo_endpoint: ${discoveryData.userinfo_endpoint}` )
        console.log( `   registration_endpoint: ${discoveryData.registration_endpoint}` )

        return {
            success: true,
            discoveryUrl,
            endpoints: {
                authorization: discoveryData.authorization_endpoint,
                token: discoveryData.token_endpoint,
                userinfo: discoveryData.userinfo_endpoint,
                registration: discoveryData.registration_endpoint
            },
            fullDiscovery: discoveryData
        }
    }


    static async #performRegistration( { discoveryData, oauth21Config, baseUrl, requestChain, useDynamicRegistration = false } ) {
        const registrationUrl = discoveryData.endpoints.registration

        // For dynamic registration, check if provider supports it
        if( useDynamicRegistration ) {
            if( !registrationUrl ) {
                console.log( '❌ Dynamic Client Registration requested but provider does not support it!' )
                console.log( '   No registration endpoint found in discovery metadata' )
                console.log( '   Neither ScaleKit nor FlowMCP currently expose DCR endpoints' )
                console.log( '   📋 Note: DCR is supported by these providers but endpoints are not publicly available' )
                console.log( '   💡 Workaround: Use pre-configured credentials from .auth.env' )
                throw new Error( 'Provider does not expose Dynamic Client Registration endpoint. Please use pre-configured credentials or contact provider.' )
            }
            console.log( '🚀 Using Dynamic Client Registration (DCR)' )
            console.log( `📝 Registration endpoint: ${registrationUrl}` )
        }
        // Check if provider supports dynamic client registration
        else if( !registrationUrl ) {
            console.log( '🔧 No registration endpoint found - using pre-configured client credentials' )
            console.log( `🔑 Client ID: ${oauth21Config.clientId}` )
            console.log( `🔐 Client Secret: ${oauth21Config.clientSecret ? '[CONFIGURED]' : '[MISSING]'}` )

            requestChain.push( {
                step: 'oauth_registration',
                request: null,
                response: {
                    status: 'N/A',
                    statusText: 'Using pre-configured client credentials',
                    headers: {},
                    body: {
                        note: 'Provider does not support dynamic client registration',
                        using_preconfigured: true
                    }
                }
            } )

            return {
                success: true,
                clientId: oauth21Config.clientId,
                clientSecret: oauth21Config.clientSecret,
                registrationResponse: {
                    note: 'Using pre-configured client credentials',
                    client_id: oauth21Config.clientId,
                    using_preconfigured: true
                }
            }
        }

        // Dynamic registration flow for providers that support it
        console.log( '🔧 Preparing registration data...' )
        const redirectUri = `${baseUrl}/auth/callback`
        const registrationData = {
            client_name: 'OAuth Middleware Tester',
            redirect_uris: [ redirectUri ],
            grant_types: [ 'authorization_code' ],
            response_types: [ 'code' ],
            token_endpoint_auth_method: 'client_secret_post'
        }

        console.log( `🌐 Making registration request to: ${registrationUrl}` )
        console.log( '📤 Registration data:', JSON.stringify( registrationData, null, 2 ) )

        const response = await StreamableTransport.makeRequest( {
            baseUrl: new URL( registrationUrl ).origin,
            routePath: new URL( registrationUrl ).pathname,
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: registrationData,
            timeout: 30000
        } )

        console.log( `📨 Registration response received: ${response.status} ${response.statusText}` )
        console.log( '📥 Response body:', JSON.stringify( response.body, null, 2 ) )

        requestChain.push( {
            step: 'oauth_registration',
            request: response.requestDetails,
            response: {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
                body: response.body
            }
        } )

        if( !response.success ) {
            throw new Error( `Registration failed: ${response.status} ${response.statusText}` )
        }

        return {
            success: true,
            clientId: response.body.client_id,
            clientSecret: response.body.client_secret,
            registrationResponse: response.body
        }
    }


    static async #prepareAuthorization( { discoveryData, registrationResult, oauth21Config, baseUrl, routePath, requestChain } ) {
        // Dynamische Werte aus übergebenen Parametern verwenden (CLAUDE.md konform)
        const { scope, organizationId } = oauth21Config
        const redirectUri = `${baseUrl}/auth/callback`

        const codeVerifier = crypto.randomBytes( 32 ).toString( 'base64url' )
        const codeChallenge = crypto.createHash( 'sha256' ).update( codeVerifier ).digest( 'base64url' )

        const authParams = new URLSearchParams( {
            response_type: 'code',
            client_id: registrationResult.clientId,
            redirect_uri: redirectUri,
            scope,
            state: crypto.randomBytes( 16 ).toString( 'hex' ),
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            organization_id: organizationId
        } )

        const authorizationUrl = `${discoveryData.endpoints.authorization}?${authParams.toString()}`

        return {
            success: true,
            authorizationUrl,
            redirectUri,
            codeVerifier,
            codeChallenge,
            state: authParams.get( 'state' )
        }
    }


    static async #performBrowserAuthorization( { browser, authorizationResult, browserTimeout, requestChain } ) {
        console.log( '🖥️  Using existing MCP server for callback (no separate server needed)...' )
        console.log( `🌐 Opening browser to: ${authorizationResult.authorizationUrl}` )
        console.log( '👆 Please complete the OAuth login in the browser window' )

        // Open browser to authorization URL
        const page = await browser.newPage()
        await page.goto( authorizationResult.authorizationUrl )

        // Wait for callback URL to be reached in the browser
        const authCodePromise = new Promise( ( resolve, reject ) => {
            const timeout = setTimeout( () => {
                reject( new Error( `Browser authorization timeout after ${browserTimeout}ms` ) )
            }, browserTimeout )

            // Wait for navigation to callback URL with authorization code
            page.waitForFunction(
                ( redirectUri ) => window.location.href.includes( redirectUri.split( '?' )[0] ),
                { timeout: browserTimeout },
                authorizationResult.redirectUri
            ).then( async () => {
                clearTimeout( timeout )

                const currentUrl = await page.url()
                console.log( `📍 Callback URL reached: ${currentUrl}` )

                // Extract authorization code from URL
                const urlParams = new URLSearchParams( new URL( currentUrl ).search )
                const code = urlParams.get( 'code' )
                const state = urlParams.get( 'state' )
                const error = urlParams.get( 'error' )

                if( error ) {
                    console.log( `❌ OAuth authorization failed: ${error}` )
                    reject( new Error( `OAuth authorization failed: ${error}` ) )
                    return
                }

                if( !code ) {
                    console.log( '❌ No authorization code received' )
                    reject( new Error( 'No authorization code received' ) )
                    return
                }

                console.log( `✅ Authorization code received: ${code.substring( 0, 10 )}...` )
                resolve( { code, state } )
            } ).catch( reject )
        } )

        // Wait for authorization code
        const authCode = await authCodePromise

        console.log( '🔐 Browser authorization completed successfully!' )
        await page.close()

        requestChain.push( {
            step: 'oauth_browser_authorization',
            request: { authorizationUrl: authorizationResult.authorizationUrl },
            response: { authCode: authCode.code, state: authCode.state }
        } )

        return {
            success: true,
            authCode: authCode.code,
            state: authCode.state
        }
    }


    static async #performTokenExchange( { discoveryData, authCodeResult, oauth21Config, authorizationResult, requestChain } ) {
        const tokenData = {
            grant_type: 'authorization_code',
            code: authCodeResult.authCode,
            redirect_uri: authorizationResult.redirectUri,
            client_id: oauth21Config.clientId,
            client_secret: oauth21Config.clientSecret,
            code_verifier: authorizationResult.codeVerifier
        }

        const tokenBodyString = new URLSearchParams( tokenData ).toString()
        console.log( `🔍 DEBUG Token Exchange:` )
        console.log( `   URL: ${discoveryData.endpoints.token}` )
        console.log( `   Body: ${tokenBodyString}` )

        const response = await StreamableTransport.makeRequest( {
            baseUrl: new URL( discoveryData.endpoints.token ).origin,
            routePath: new URL( discoveryData.endpoints.token ).pathname,
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: tokenBodyString,
            timeout: 30000
        } )

        console.log( `🔍 DEBUG Response: ${response.status} ${response.statusText}` )
        console.log( `🔍 DEBUG Response Body:`, response.body )

        requestChain.push( {
            step: 'oauth_token_exchange',
            request: response.requestDetails,
            response: {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
                body: response.body
            }
        } )

        if( !response.success ) {
            throw new Error( `Token exchange failed: ${response.status} ${response.statusText}` )
        }

        return {
            success: true,
            tokens: response.body,
            accessToken: response.body.access_token
        }
    }


    static async #validateToken( { discoveryData, tokenResult, requestChain } ) {
        const response = await StreamableTransport.makeRequest( {
            baseUrl: new URL( discoveryData.endpoints.userinfo ).origin,
            routePath: new URL( discoveryData.endpoints.userinfo ).pathname,
            method: 'GET',
            headers: { 'Authorization': `Bearer ${tokenResult.accessToken}` },
            timeout: 30000
        } )

        requestChain.push( {
            step: 'oauth_token_validation',
            request: response.requestDetails,
            response: {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
                body: response.body
            }
        } )

        if( !response.success ) {
            throw new Error( `Token validation failed: ${response.status} ${response.statusText}` )
        }

        return {
            success: true,
            userInfo: response.body
        }
    }


    static async #performMcpFlow( { baseUrl, routePath, tokenResult, requestChain } ) {
        const authHeaders = { 'Authorization': `Bearer ${tokenResult.accessToken}` }

        const initializeResponse = await StreamableTransport.sendMcpRequest( {
            baseUrl,
            routePath,
            mcpMethod: 'initialize',
            mcpParams: {
                protocolVersion: '2024-11-05',
                capabilities: {},
                clientInfo: { name: 'oauth-test-client', version: '1.0.0' }
            },
            authHeaders,
            timeout: 30000
        } )

        requestChain.push( {
            step: 'mcp_initialize_with_oauth',
            request: initializeResponse.requestDetails,
            response: {
                status: initializeResponse.status,
                statusText: initializeResponse.statusText,
                headers: initializeResponse.headers,
                body: initializeResponse.body
            }
        } )

        const initAnalysis = StreamableTransport.analyzeMcpResponse( { response: initializeResponse } )

        if( !initializeResponse.success || !initAnalysis.isValidMcp || initAnalysis.hasError ) {
            return {
                success: false,
                error: initAnalysis.errorData?.message ? initAnalysis.errorData.message : `HTTP ${initializeResponse.status}`,
                errorMessage: initAnalysis.errorData?.message,
                httpStatus: initializeResponse.status,
                step: 'initialize'
            }
        }

        // Extract session ID from initialize response headers (required for subsequent MCP requests)
        const sessionId = initializeResponse.headers['mcp-session-id']

        const toolsResponse = await StreamableTransport.sendMcpRequest( {
            baseUrl,
            routePath,
            mcpMethod: 'tools/list',
            mcpParams: {},
            authHeaders,
            sessionId,
            timeout: 30000
        } )

        requestChain.push( {
            step: 'mcp_tools_list_with_oauth',
            request: toolsResponse.requestDetails,
            response: {
                status: toolsResponse.status,
                statusText: toolsResponse.statusText,
                headers: toolsResponse.headers,
                body: toolsResponse.body
            }
        } )

        const toolsAnalysis = StreamableTransport.analyzeMcpResponse( { response: toolsResponse } )

        if( !toolsResponse.success || !toolsAnalysis.isValidMcp || toolsAnalysis.hasError ) {
            return {
                success: false,
                error: toolsAnalysis.errorData?.message ? toolsAnalysis.errorData.message : `HTTP ${toolsResponse.status}`,
                errorMessage: toolsAnalysis.errorData?.message,
                httpStatus: toolsResponse.status,
                step: 'tools/list'
            }
        }

        const tools = toolsAnalysis.resultData?.tools ? toolsAnalysis.resultData.tools : []

        // Test first tool if available (like Bearer token test)
        let toolTestResult = null
        if( tools.length > 0 ) {
            const firstTool = tools[0]
            const toolCallResponse = await StreamableTransport.sendMcpRequest( {
                baseUrl,
                routePath,
                mcpMethod: 'tools/call',
                mcpParams: {
                    name: firstTool.name,
                    arguments: {}
                },
                authHeaders,
                sessionId,
                timeout: 30000
            } )

            requestChain.push( {
                step: 'mcp_tool_call_with_oauth',
                toolName: firstTool.name,
                request: toolCallResponse.requestDetails,
                response: {
                    status: toolCallResponse.status,
                    statusText: toolCallResponse.statusText,
                    headers: toolCallResponse.headers,
                    body: toolCallResponse.body
                }
            } )

            const toolCallAnalysis = StreamableTransport.analyzeMcpResponse( { response: toolCallResponse } )

            if( toolCallResponse.success && toolCallAnalysis.isValidMcp && !toolCallAnalysis.hasError ) {
                toolTestResult = {
                    success: true,
                    toolName: firstTool.name,
                    result: toolCallAnalysis.resultData
                }
            } else {
                toolTestResult = {
                    success: false,
                    toolName: firstTool.name,
                    error: toolCallAnalysis.errorData?.message || `HTTP ${toolCallResponse.status}`
                }
            }
        }

        return {
            success: true,
            mcpVersion: initAnalysis.mcpVersion,
            toolsFound: tools.length,
            tools: tools.map( tool => ( { name: tool.name, description: tool.description } ) ),
            toolTest: toolTestResult
        }
    }
}


export { OAuthTester }