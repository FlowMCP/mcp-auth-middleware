import { StreamableTransport } from '../helpers/StreamableTransport.mjs'
import { DiagnosticAnalyzer } from '../helpers/DiagnosticAnalyzer.mjs'


class StreamableTester {
    static async runTest( { baseUrl, routePath, timeout = 30000, expectedStatus = 200 } ) {
        console.log( '\n🔍 Starting Free Route Test...' )
        console.log( '═'.repeat( 60 ) )
        console.log( `   Endpoint: ${baseUrl}${routePath}` )
        console.log( `   Method: No Authentication (Free Access)` )
        console.log( '═'.repeat( 60 ) )

        const testResult = {
            success: false,
            testType: 'streamable_route',
            timestamp: new Date().toISOString(),
            configuration: { baseUrl, routePath, timeout, expectedStatus },
            naiveTest: null,
            diagnostics: null,
            rawData: {}
        }

        const requestChain = []

        try {
            console.log( '🛠️  Testing tools/list access...' )

            // First initialize the session
            const initResponse = await StreamableTransport.sendMcpRequest( {
                baseUrl,
                routePath,
                mcpMethod: 'initialize',
                mcpParams: {
                    protocolVersion: '2024-11-05',
                    capabilities: {},
                    clientInfo: { name: 'free-route-test-client', version: '1.0.0' }
                },
                timeout
            } )

            console.log( '🔗 Initialize response received, extracting session...' )
            let sessionId = null
            if( initResponse.headers && initResponse.headers['mcp-session-id'] ) {
                sessionId = initResponse.headers['mcp-session-id']
                console.log( `🔗 Session ID extracted: ${sessionId}` )
            }

            const naiveResponse = await StreamableTransport.sendMcpRequest( {
                baseUrl,
                routePath,
                mcpMethod: 'tools/list',
                mcpParams: {},
                timeout,
                sessionId
            } )

            requestChain.push( {
                step: 'naive_streamable_test',
                request: naiveResponse.requestDetails,
                response: {
                    status: naiveResponse.status,
                    statusText: naiveResponse.statusText,
                    headers: naiveResponse.headers,
                    body: naiveResponse.body
                }
            } )

            const naiveSuccess = naiveResponse.status === expectedStatus
            testResult.naiveTest = {
                success: naiveSuccess,
                httpStatus: naiveResponse.status,
                httpStatusText: naiveResponse.statusText,
                expectedStatus,
                message: naiveSuccess ?
                    `Successfully accessed streamable route (${naiveResponse.status})` :
                    `Unexpected status: expected ${expectedStatus}, got ${naiveResponse.status}`
            }

            if( naiveSuccess ) {
                // Analyze the MCP response to get tools
                const toolsAnalysis = StreamableTransport.analyzeMcpResponse( { response: naiveResponse } )

                if( toolsAnalysis.isValidMcp && toolsAnalysis.hasResult ) {
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

                        // Test first tool if available
                        if( tools.length > 0 ) {
                            const firstTool = tools[ 0 ]
                            console.log( `\n🔧 Calling tool: ${firstTool.name}` )

                            try {
                                const toolCallResponse = await StreamableTransport.sendMcpRequest( {
                                    baseUrl,
                                    routePath,
                                    mcpMethod: 'tools/call',
                                    mcpParams: {
                                        name: firstTool.name,
                                        arguments: this.#generateToolArguments( firstTool )
                                    },
                                    timeout,
                                    sessionId
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

                                testResult.toolCallResult = {
                                    toolName: firstTool.name,
                                    success: toolCallResponse.success && toolCallAnalysis.isValidMcp && !toolCallAnalysis.hasError,
                                    response: toolCallResponse,
                                    analysis: toolCallAnalysis
                                }
                            } catch( toolError ) {
                                console.log( `   ❌ Tool call failed: ${toolError.message}` )
                                testResult.toolCallResult = {
                                    toolName: firstTool.name,
                                    success: false,
                                    error: toolError.message
                                }
                            }
                        }
                    } else {
                        console.log( '   No tools available' )
                    }
                    console.log( '═'.repeat( 60 ) )

                    console.log( '\n✨ Test Complete!' )
                    console.log( '═'.repeat( 60 ) )
                    console.log( `   Status: ✅ SUCCESS` )
                    console.log( `   Summary: Free route accessible, ${tools.length} tools available` )
                    if( testResult.toolCallResult ) {
                        console.log( `   Tool tested: ${testResult.toolCallResult.toolName} - ${testResult.toolCallResult.success ? 'SUCCESS' : 'FAILED'}` )
                    }
                    console.log( '═'.repeat( 60 ) )

                    testResult.success = true
                    testResult.diagnostics = {
                        summary: `Free route accessible with ${tools.length} tools available`,
                        details: {
                            responseTime: 'Success',
                            contentType: naiveResponse.headers[ 'content-type' ] || 'unknown',
                            responseSize: naiveResponse.rawBody?.length || 0,
                            toolsAvailable: tools.length,
                            toolsNames: tools.map( tool => tool.name )
                        }
                    }
                } else {
                    console.log( '\n❌ Invalid MCP response or error occurred' )
                    testResult.success = false
                    testResult.diagnostics = {
                        summary: 'Free route accessible but MCP response invalid',
                        details: {
                            mcpValid: toolsAnalysis.isValidMcp,
                            hasError: toolsAnalysis.hasError,
                            errorMessage: toolsAnalysis.errorData?.message
                        }
                    }
                }
            } else {
                const errorAnalysis = DiagnosticAnalyzer.analyzeStreamableFailure( {
                    response: naiveResponse,
                    testType: 'streamable',
                    step: 'naive_test',
                    context: { expectedStatus }
                } )

                testResult.diagnostics = DiagnosticAnalyzer.buildDiagnosticReport( {
                    testType: 'streamable_route',
                    errorDetails: errorAnalysis,
                    fullContext: {
                        response: naiveResponse,
                        requestChain,
                        testConfig: testResult.configuration
                    }
                } )
            }

            testResult.rawData = {
                naiveResponse,
                requestChain
            }

        } catch( testError ) {
            testResult.success = false
            testResult.naiveTest = {
                success: false,
                error: testError.message,
                message: `Test execution failed: ${testError.message}`
            }
            testResult.diagnostics = {
                summary: 'Test execution failed with unexpected error',
                aiDiagnostics: {
                    primaryIssue: testError.message,
                    detectedProblems: [ 'Test framework error', 'Unexpected exception' ],
                    recommendedActions: [ 'Check test configuration', 'Verify network connectivity' ]
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

        Object.keys( properties ).forEach( key => {
            const property = properties[ key ]
            switch( property.type ) {
                case 'string':
                    args[ key ] = property.default || 'test'
                    break
                case 'number':
                    args[ key ] = property.default || 42
                    break
                case 'boolean':
                    args[ key ] = property.default !== undefined ? property.default : true
                    break
                case 'array':
                    args[ key ] = property.default || []
                    break
                case 'object':
                    args[ key ] = property.default || {}
                    break
                default:
                    args[ key ] = property.default || null
            }
        } )

        return args
    }


    static async runAdvancedTest( { baseUrl, routePath, timeout = 30000 } ) {
        const testMethods = [ 'GET', 'POST', 'HEAD', 'OPTIONS' ]
        const results = {}

        for( const method of testMethods ) {
            const methodResult = await StreamableTransport.makeRequest( {
                baseUrl,
                routePath,
                method,
                timeout
            } )

            results[ method.toLowerCase() ] = {
                status: methodResult.status,
                statusText: methodResult.statusText,
                headers: methodResult.headers,
                success: methodResult.success,
                bodySize: methodResult.rawBody?.length || 0
            }
        }

        const analysis = {
            supportedMethods: [],
            unsupportedMethods: [],
            corsEnabled: false,
            serverInfo: {}
        }

        Object.entries( results )
            .forEach( ( [ method, result ] ) => {
                if( result.status < 400 ) {
                    analysis.supportedMethods.push( method.toUpperCase() )
                } else {
                    analysis.unsupportedMethods.push( method.toUpperCase() )
                }
            } )

        if( results.options && results.options.headers[ 'access-control-allow-origin' ] ) {
            analysis.corsEnabled = true
        }

        const serverHeader = results.get?.headers?.server || results.post?.headers?.server
        if( serverHeader ) {
            analysis.serverInfo.server = serverHeader
        }

        return {
            methodTests: results,
            analysis,
            recommendations: this.#generateRecommendations( analysis )
        }
    }


    static #generateRecommendations( analysis ) {
        const recommendations = []

        if( analysis.supportedMethods.includes( 'GET' ) && analysis.supportedMethods.includes( 'POST' ) ) {
            recommendations.push( 'Route supports both GET and POST - good for flexible access' )
        }

        if( !analysis.corsEnabled ) {
            recommendations.push( 'CORS not detected - may need configuration for browser access' )
        }

        if( analysis.unsupportedMethods.length === 0 ) {
            recommendations.push( 'All HTTP methods supported - very permissive configuration' )
        }

        if( analysis.supportedMethods.length === 0 ) {
            recommendations.push( 'No HTTP methods supported - check server configuration' )
        }

        return recommendations
    }
}


export { StreamableTester }