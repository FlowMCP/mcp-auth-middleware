import { StreamableTransport } from '../helpers/StreamableTransport.mjs'
import { DiagnosticAnalyzer } from '../helpers/DiagnosticAnalyzer.mjs'


class BearerTester {
    static async runTest( { baseUrl, routePath, bearerToken, timeout = 30000, testUnauthorized = true, expectedUnauthorizedStatus = 401 } ) {
        console.log( '\n🔍 Starting Bearer Test...' )
        console.log( '═'.repeat( 60 ) )
        console.log( `   Endpoint: ${baseUrl}${routePath}` )
        console.log( `   Method: Bearer Token Authentication` )
        console.log( '═'.repeat( 60 ) )

        const testResult = {
            success: false,
            testType: 'bearer_streamable',
            timestamp: new Date().toISOString(),
            configuration: { baseUrl, routePath, bearerToken: `${bearerToken.substring( 0, 8 )}...`, timeout },
            naiveTest: null,
            authTest: null,
            diagnostics: null,
            rawData: {}
        }

        const requestChain = []

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
                    timeout
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
                    console.log( `   🔒 Security Status: Authentication required (Good!)` )
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

                if( !naiveSuccess && naiveResponse.status < 400 ) {
                    testResult.naiveTest.message = 'WARNING: Route appears to be publicly accessible without authentication'
                }
            }

            const authHeaders = { 'Authorization': `Bearer ${bearerToken}` }

            console.log( '🔑 Testing with Bearer token...' )
            const initializeResponse = await StreamableTransport.sendMcpRequest( {
                baseUrl,
                routePath,
                mcpMethod: 'initialize',
                mcpParams: {
                    protocolVersion: '2024-11-05',
                    capabilities: {},
                    clientInfo: { name: 'bearer-test-client', version: '1.0.0' }
                },
                authHeaders,
                timeout
            } )

            requestChain.push( {
                step: 'mcp_initialize_with_bearer',
                request: initializeResponse.requestDetails,
                response: {
                    status: initializeResponse.status,
                    statusText: initializeResponse.statusText,
                    headers: initializeResponse.headers,
                    body: initializeResponse.body
                }
            } )

            const initAnalysis = StreamableTransport.analyzeMcpResponse( { response: initializeResponse } )

            // Extract session ID from response headers for Streamable HTTP
            let sessionId = null
            if( initializeResponse.headers && initializeResponse.headers['mcp-session-id'] ) {
                sessionId = initializeResponse.headers['mcp-session-id']
                console.log( `🔗 Session ID extracted: ${sessionId}` )
            } else {
                console.log( '⚠️  No session ID in response headers' )
            }

            if( !initializeResponse.success || !initAnalysis.isValidMcp || initAnalysis.hasError ) {
                const errorAnalysis = DiagnosticAnalyzer.analyzeStreamableFailure( {
                    response: initializeResponse,
                    testType: 'bearer',
                    step: 'mcp_initialize',
                    context: { bearerToken: true }
                } )

                testResult.authTest = {
                    success: false,
                    step: 'initialize',
                    error: initAnalysis.errorData?.message || `HTTP ${initializeResponse.status}`,
                    mcpAnalysis: initAnalysis
                }

                testResult.diagnostics = DiagnosticAnalyzer.buildDiagnosticReport( {
                    testType: 'bearer_streamable',
                    errorDetails: errorAnalysis,
                    fullContext: {
                        response: initializeResponse,
                        requestChain,
                        testConfig: testResult.configuration
                    }
                } )

                testResult.rawData = { requestChain, initializeResponse, initAnalysis }
                return testResult
            }

            console.log( '🛠️  Requesting tools list...' )
            const toolsResponse = await StreamableTransport.sendMcpRequest( {
                baseUrl,
                routePath,
                mcpMethod: 'tools/list',
                mcpParams: {},
                authHeaders,
                timeout,
                sessionId
            } )

            requestChain.push( {
                step: 'mcp_tools_list_with_bearer',
                request: toolsResponse.requestDetails,
                response: {
                    status: toolsResponse.status,
                    statusText: toolsResponse.statusText,
                    headers: toolsResponse.headers,
                    body: toolsResponse.body
                }
            } )

            console.log( '📊 Analyzing tools response...' )
            const toolsAnalysis = StreamableTransport.analyzeMcpResponse( { response: toolsResponse } )
            console.log( `📋 Tools analysis result: ${toolsAnalysis.isValidMcp ? 'Valid MCP' : 'Invalid MCP'}, Error: ${toolsAnalysis.hasError}` )

            if( !toolsResponse.success || !toolsAnalysis.isValidMcp || toolsAnalysis.hasError ) {
                const errorAnalysis = DiagnosticAnalyzer.analyzeStreamableFailure( {
                    response: toolsResponse,
                    testType: 'bearer',
                    step: 'mcp_tools_list',
                    context: { bearerToken: true }
                } )

                testResult.authTest = {
                    success: false,
                    step: 'tools/list',
                    error: toolsAnalysis.errorData?.message || `HTTP ${toolsResponse.status}`,
                    mcpAnalysis: toolsAnalysis
                }

                testResult.diagnostics = DiagnosticAnalyzer.buildDiagnosticReport( {
                    testType: 'bearer_streamable',
                    errorDetails: errorAnalysis,
                    fullContext: {
                        response: toolsResponse,
                        requestChain,
                        testConfig: testResult.configuration
                    }
                } )

                testResult.rawData = { requestChain, toolsResponse, toolsAnalysis }
                return testResult
            }

            const tools = toolsAnalysis.resultData?.tools || []

            // Log available MCP tools
            console.log( '\n📦 Available MCP Tools:' )
            console.log( '═'.repeat( 60 ) )
            if( tools.length > 0 ) {
                tools.forEach( ( tool, index ) => {
                    console.log( `${index + 1}. ${tool.name}` )
                    if( tool.description ) {
                        console.log( `   └─ ${tool.description}` )
                    }
                    if( tool.inputSchema?.properties ) {
                        const props = Object.keys( tool.inputSchema.properties )
                        if( props.length > 0 ) {
                            console.log( `   └─ Parameters: ${props.join( ', ' )}` )
                        }
                    }
                } )
            } else {
                console.log( '   No tools available' )
            }
            console.log( '═'.repeat( 60 ) )

            let toolCallResult = null

            if( tools.length > 0 ) {
                const firstTool = tools[ 0 ]
                console.log( `\n🔧 Calling tool: ${firstTool.name}` )
                const toolCallResponse = await StreamableTransport.sendMcpRequest( {
                    baseUrl,
                    routePath,
                    mcpMethod: 'tools/call',
                    mcpParams: {
                        name: firstTool.name,
                        arguments: this.#generateToolArguments( firstTool )
                    },
                    authHeaders,
                    timeout,
                    sessionId
                } )

                requestChain.push( {
                    step: 'mcp_tool_call_with_bearer',
                    request: toolCallResponse.requestDetails,
                    response: {
                        status: toolCallResponse.status,
                        statusText: toolCallResponse.statusText,
                        headers: toolCallResponse.headers,
                        body: toolCallResponse.body
                    }
                } )

                const toolCallAnalysis = StreamableTransport.analyzeMcpResponse( { response: toolCallResponse } )

                // Log tool response
                console.log( `\n📨 Tool Response:` )
                console.log( '─'.repeat( 40 ) )
                if( toolCallAnalysis.isValidMcp && !toolCallAnalysis.hasError ) {
                    const result = toolCallAnalysis.resultData?.content
                    if( result ) {
                        if( Array.isArray( result ) ) {
                            result.forEach( item => {
                                if( item.type === 'text' ) {
                                    console.log( `   ${item.text}` )
                                } else {
                                    console.log( `   ${JSON.stringify( item, null, 2 )}` )
                                }
                            } )
                        } else {
                            console.log( `   ${JSON.stringify( result, null, 2 )}` )
                        }
                    }
                } else {
                    console.log( `   ❌ Error: ${toolCallAnalysis.errorData?.message || 'Unknown error'}` )
                }
                console.log( '─'.repeat( 40 ) )

                toolCallResult = {
                    toolName: firstTool.name,
                    success: toolCallResponse.success && toolCallAnalysis.isValidMcp && !toolCallAnalysis.hasError,
                    response: toolCallResponse,
                    analysis: toolCallAnalysis
                }
            }

            testResult.success = true
            testResult.authTest = {
                success: true,
                stepsCompleted: [ 'initialize', 'tools/list', toolCallResult ? 'tools/call' : null ].filter( Boolean ),
                toolsFound: tools.length,
                toolCallResult,
                summary: `Bearer authentication successful, ${tools.length} tools available`
            }

            testResult.diagnostics = {
                summary: 'Bearer token authentication and MCP protocol working correctly',
                details: {
                    authenticationMethod: 'Bearer Token',
                    mcpProtocolVersion: initAnalysis.mcpVersion,
                    toolsAvailable: tools.length,
                    toolsNames: tools.map( tool => tool.name )
                }
            }

            testResult.rawData = {
                requestChain,
                initializeResponse,
                toolsResponse,
                toolCallResult,
                tools
            }

            console.log( '\n✨ Test Complete!' )
            console.log( '═'.repeat( 60 ) )
            console.log( `   Status: ${testResult.success ? '✅ SUCCESS' : '❌ FAILED'}` )
            console.log( `   Summary: Bearer authentication successful, ${tools.length} tools available` )
            if( toolCallResult ) {
                console.log( `   Tool tested: ${toolCallResult.toolName} - ${toolCallResult.success ? 'SUCCESS' : 'FAILED'}` )
            }
            console.log( '═'.repeat( 60 ) )

        } catch( testError ) {
            testResult.success = false
            testResult.authTest = {
                success: false,
                error: testError.message,
                step: 'test_execution'
            }
            testResult.diagnostics = {
                summary: 'Bearer test execution failed with unexpected error',
                aiDiagnostics: {
                    primaryIssue: testError.message,
                    detectedProblems: [ 'Test framework error', 'Unexpected exception during bearer test' ],
                    recommendedActions: [ 'Check bearer token format', 'Verify server configuration', 'Review test parameters' ]
                }
            }
            testResult.rawData = { testError: testError.message, requestChain }
        }

        return testResult
    }


    static #generateToolArguments( tool ) {
        if( !tool.inputSchema || !tool.inputSchema.properties ) {
            return {}
        }

        const args = {}
        const properties = tool.inputSchema.properties

        Object.entries( properties )
            .forEach( ( [ key, schema ] ) => {
                if( schema.type === 'string' ) {
                    args[ key ] = tool.name === 'echo' ? 'Hello MCP Bearer Test!' : 'test-value'
                } else if( schema.type === 'number' ) {
                    args[ key ] = 42
                } else if( schema.type === 'boolean' ) {
                    args[ key ] = true
                } else if( schema.type === 'array' ) {
                    args[ key ] = [ 'test-item' ]
                } else {
                    args[ key ] = null
                }
            } )

        return args
    }
}


export { BearerTester }