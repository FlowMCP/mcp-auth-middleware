class DiagnosticAnalyzer {
    static analyzeStreamableFailure( { response, testType, step, context = {} } ) {
        const analysis = {
            problemCategory: 'unknown_error',
            likelyCause: 'Undefined error occurred',
            aiDiagnostics: [],
            suggestedActions: [],
            technicalDetails: {},
            severity: 'medium'
        }

        if( !response.success && response.error ) {
            analysis.problemCategory = 'network_connectivity'
            analysis.likelyCause = `Network request failed: ${response.error}`
            analysis.severity = 'high'
            analysis.aiDiagnostics.push( `Connection to ${response.requestDetails?.url} failed` )
            analysis.aiDiagnostics.push( `Error type: ${response.errorType}` )
            analysis.suggestedActions.push( 'Check if server is running' )
            analysis.suggestedActions.push( 'Verify baseUrl and routePath are correct' )
            analysis.suggestedActions.push( 'Check network connectivity' )
            analysis.technicalDetails.networkError = response.error
        } else if( response.status >= 400 && response.status < 500 ) {
            analysis.problemCategory = 'authentication_authorization'
            analysis.severity = 'high'

            if( response.status === 401 ) {
                analysis.likelyCause = 'Authentication required or token invalid'
                analysis.aiDiagnostics.push( 'Server rejected request due to missing or invalid authentication' )
                if( testType === 'streamable' ) {
                    analysis.aiDiagnostics.push( 'This might be expected for public routes - check if route requires authentication' )
                    analysis.severity = 'low'
                } else {
                    analysis.suggestedActions.push( 'Verify authentication token is valid' )
                    analysis.suggestedActions.push( 'Check token expiration' )
                    analysis.suggestedActions.push( 'Ensure proper Authorization header format' )
                }
            } else if( response.status === 403 ) {
                analysis.likelyCause = 'Authentication valid but insufficient permissions'
                analysis.aiDiagnostics.push( 'Server authenticated request but denied access' )
                analysis.suggestedActions.push( 'Verify token has required scopes/permissions' )
                analysis.suggestedActions.push( 'Check if user/client has access to this resource' )
            } else if( response.status === 404 ) {
                analysis.likelyCause = 'Endpoint not found'
                analysis.aiDiagnostics.push( `Route ${response.requestDetails?.url} does not exist` )
                analysis.suggestedActions.push( 'Verify routePath is correct' )
                analysis.suggestedActions.push( 'Check server routing configuration' )
            } else {
                analysis.likelyCause = `Client error: ${response.status} ${response.statusText}`
                analysis.aiDiagnostics.push( `HTTP ${response.status}: ${response.statusText}` )
            }

            analysis.technicalDetails.httpStatus = response.status
            analysis.technicalDetails.httpStatusText = response.statusText
            analysis.technicalDetails.responseHeaders = response.headers
        } else if( response.status >= 500 ) {
            analysis.problemCategory = 'server_error'
            analysis.likelyCause = `Server internal error: ${response.status} ${response.statusText}`
            analysis.severity = 'high'
            analysis.aiDiagnostics.push( 'Server encountered an internal error' )
            analysis.suggestedActions.push( 'Check server logs for detailed error information' )
            analysis.suggestedActions.push( 'Verify server configuration' )
            analysis.suggestedActions.push( 'Contact server administrator if problem persists' )
            analysis.technicalDetails.httpStatus = response.status
            analysis.technicalDetails.httpStatusText = response.statusText
        } else if( response.parseError ) {
            analysis.problemCategory = 'response_format_error'
            analysis.likelyCause = `Invalid JSON response: ${response.parseError}`
            analysis.severity = 'medium'
            analysis.aiDiagnostics.push( 'Server returned non-JSON or malformed JSON response' )
            analysis.aiDiagnostics.push( `Parse error: ${response.parseError}` )
            analysis.suggestedActions.push( 'Check if server is returning proper JSON' )
            analysis.suggestedActions.push( 'Verify Content-Type headers' )
            analysis.technicalDetails.parseError = response.parseError
            analysis.technicalDetails.rawResponse = response.rawBody
        }

        const mcpAnalysis = this.#analyzeMcpSpecific( { response, step, context } )
        if( mcpAnalysis.isMcpRelated ) {
            analysis.problemCategory = mcpAnalysis.category
            analysis.likelyCause = mcpAnalysis.cause
            analysis.aiDiagnostics.push( ...mcpAnalysis.diagnostics )
            analysis.suggestedActions.push( ...mcpAnalysis.actions )
            analysis.technicalDetails.mcpError = mcpAnalysis.details
        }

        if( context.oauth21 ) {
            const oauthAnalysis = this.#analyzeOAuthSpecific( { response, step, context } )
            if( oauthAnalysis.isOAuthRelated ) {
                analysis.problemCategory = oauthAnalysis.category
                analysis.likelyCause = oauthAnalysis.cause
                analysis.aiDiagnostics.push( ...oauthAnalysis.diagnostics )
                analysis.suggestedActions.push( ...oauthAnalysis.actions )
                analysis.technicalDetails.oauthError = oauthAnalysis.details
            }
        }

        return analysis
    }


    static #analyzeMcpSpecific( { response, step, context } ) {
        const analysis = {
            isMcpRelated: false,
            category: 'mcp_protocol_error',
            cause: 'MCP protocol violation',
            diagnostics: [],
            actions: [],
            details: {}
        }

        if( !step || !step.includes( 'mcp' ) ) {
            return analysis
        }

        analysis.isMcpRelated = true

        if( response.success && response.body ) {
            if( !response.body.jsonrpc ) {
                analysis.diagnostics.push( 'Response missing required jsonrpc field' )
                analysis.actions.push( 'Verify server implements MCP protocol correctly' )
                analysis.details.missingField = 'jsonrpc'
            }

            if( response.body.error ) {
                analysis.cause = `MCP error: ${response.body.error.message || 'Unknown MCP error'}`
                analysis.diagnostics.push( `MCP protocol error: ${response.body.error.code || 'no code'} - ${response.body.error.message || 'no message'}` )
                analysis.actions.push( 'Check MCP method parameters' )
                analysis.actions.push( 'Verify MCP server supports requested method' )
                analysis.details.mcpErrorCode = response.body.error.code
                analysis.details.mcpErrorMessage = response.body.error.message
            }

            if( step === 'mcp_initialize' && !response.body.result?.capabilities ) {
                analysis.diagnostics.push( 'MCP initialize response missing capabilities' )
                analysis.actions.push( 'Check MCP server initialization logic' )
            }

            if( step === 'mcp_tools_list' && !response.body.result?.tools ) {
                analysis.diagnostics.push( 'MCP tools/list response missing tools array' )
                analysis.actions.push( 'Verify MCP server has tools registered' )
            }
        }

        return analysis
    }


    static #analyzeOAuthSpecific( { response, step, context } ) {
        const analysis = {
            isOAuthRelated: false,
            category: 'oauth_flow_error',
            cause: 'OAuth flow error',
            diagnostics: [],
            actions: [],
            details: {}
        }

        if( !step || !step.includes( 'oauth' ) && !step.includes( 'discovery' ) && !step.includes( 'registration' ) && !step.includes( 'token' ) ) {
            return analysis
        }

        analysis.isOAuthRelated = true

        if( step === 'oauth_discovery' ) {
            analysis.diagnostics.push( 'OAuth discovery endpoint failed' )
            analysis.actions.push( 'Verify providerUrl is correct' )
            analysis.actions.push( 'Check if OAuth provider is accessible' )
            analysis.details.discoveryUrl = context.discoveryUrl
        }

        if( step === 'oauth_registration' ) {
            analysis.diagnostics.push( 'OAuth client registration failed' )
            analysis.actions.push( 'Check client_id and client_secret are valid' )
            analysis.actions.push( 'Verify registration endpoint accepts dynamic registration' )
            analysis.details.registrationEndpoint = context.registrationEndpoint
        }

        if( step === 'oauth_token_exchange' ) {
            analysis.diagnostics.push( 'OAuth token exchange failed' )
            analysis.actions.push( 'Verify authorization code is valid and not expired' )
            analysis.actions.push( 'Check PKCE verifier matches challenge' )
            analysis.actions.push( 'Ensure redirect_uri matches exactly' )
            analysis.details.tokenEndpoint = context.tokenEndpoint
        }

        return analysis
    }


    static buildDiagnosticReport( { testType, errorDetails, fullContext } ) {
        const timestamp = new Date().toISOString()

        const report = {
            timestamp,
            testType,
            summary: {
                success: false,
                problemCategory: errorDetails.problemCategory,
                severity: errorDetails.severity,
                likelyCause: errorDetails.likelyCause
            },
            aiDiagnostics: {
                primaryIssue: errorDetails.likelyCause,
                detectedProblems: errorDetails.aiDiagnostics,
                recommendedActions: errorDetails.suggestedActions,
                confidence: this.#calculateConfidence( errorDetails )
            },
            technicalDetails: {
                ...errorDetails.technicalDetails,
                fullResponse: fullContext.response,
                requestChain: fullContext.requestChain || [],
                testConfiguration: fullContext.testConfig || {}
            },
            debuggingInfo: {
                nextSteps: this.#generateNextSteps( errorDetails ),
                commonCauses: this.#getCommonCauses( errorDetails.problemCategory ),
                relatedDocumentation: this.#getRelatedDocs( errorDetails.problemCategory )
            }
        }

        return report
    }


    static #calculateConfidence( errorDetails ) {
        if( errorDetails.severity === 'high' && errorDetails.technicalDetails.httpStatus ) {
            return 'high'
        }
        if( errorDetails.aiDiagnostics.length >= 2 ) {
            return 'medium'
        }
        return 'low'
    }


    static #generateNextSteps( errorDetails ) {
        const steps = [ ...errorDetails.suggestedActions ]

        if( errorDetails.problemCategory === 'network_connectivity' ) {
            steps.push( 'Test with curl or similar tool to isolate the issue' )
        }

        if( errorDetails.problemCategory === 'authentication_authorization' ) {
            steps.push( 'Test with a known-good token if available' )
        }

        return steps
    }


    static #getCommonCauses( category ) {
        const causes = {
            'network_connectivity': [ 'Server not running', 'Wrong URL/port', 'Firewall blocking' ],
            'authentication_authorization': [ 'Expired token', 'Wrong token format', 'Insufficient permissions' ],
            'mcp_protocol_error': [ 'Wrong MCP method', 'Invalid parameters', 'Server not MCP compliant' ],
            'oauth_flow_error': [ 'Invalid client credentials', 'Wrong OAuth configuration', 'Expired authorization code' ]
        }

        return causes[ category ] || [ 'Unknown error pattern' ]
    }


    static #getRelatedDocs( category ) {
        const docs = {
            'mcp_protocol_error': [ 'https://modelcontextprotocol.io/docs/protocol' ],
            'oauth_flow_error': [ 'https://oauth.net/2/', 'https://tools.ietf.org/html/rfc6749' ],
            'authentication_authorization': [ 'https://tools.ietf.org/html/rfc6750' ]
        }

        return docs[ category ] || []
    }
}


export { DiagnosticAnalyzer }