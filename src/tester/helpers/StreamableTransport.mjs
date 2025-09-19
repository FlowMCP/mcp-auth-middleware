class StreamableTransport {
    static async makeRequest( { baseUrl, routePath, method = 'POST', headers = {}, body = null, timeout = 30000 } ) {
        const fullUrl = `${baseUrl}${routePath}`

        const defaultHeaders = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream'
        }

        const finalHeaders = { ...defaultHeaders, ...headers }

        const requestOptions = {
            method,
            headers: finalHeaders,
            ...(body && {
                body: typeof body === 'string' ? body : JSON.stringify( body )
            })
        }

        const controller = new AbortController()
        const timeoutId = setTimeout( () => controller.abort(), timeout )
        requestOptions.signal = controller.signal

        let response
        let responseBody
        let parseError = null

        try {
            response = await fetch( fullUrl, requestOptions )
            clearTimeout( timeoutId )

            const responseText = await response.text()

            try {
                // Handle SSE format (event: message\ndata: {...})
                if( responseText.startsWith('event: message\ndata: ') ) {
                    const dataLine = responseText.split('\n').find( line => line.startsWith('data: ') )
                    if( dataLine ) {
                        const jsonData = dataLine.substring(6) // Remove 'data: '
                        responseBody = JSON.parse( jsonData )
                    } else {
                        responseBody = responseText
                    }
                } else {
                    responseBody = responseText ? JSON.parse( responseText ) : null
                }
            } catch( jsonError ) {
                parseError = jsonError.message
                responseBody = responseText
            }

            const result = {
                success: response.ok,
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries( response.headers.entries() ),
                body: responseBody,
                rawBody: responseText,
                parseError,
                requestDetails: {
                    url: fullUrl,
                    method,
                    headers: finalHeaders,
                    body
                }
            }

            return result

        } catch( fetchError ) {
            clearTimeout( timeoutId )

            const errorResult = {
                success: false,
                error: fetchError.message,
                errorType: fetchError.name,
                requestDetails: {
                    url: fullUrl,
                    method,
                    headers: finalHeaders,
                    body
                }
            }

            return errorResult
        }
    }


    static createMcpRequest( { method, params = {}, id = 1 } ) {
        const mcpRequest = {
            jsonrpc: '2.0',
            id,
            method,
            params
        }

        return mcpRequest
    }


    static async sendMcpRequest( { baseUrl, routePath, mcpMethod, mcpParams = {}, authHeaders = {}, timeout = 30000, sessionId = null } ) {
        const mcpRequest = this.createMcpRequest( {
            method: mcpMethod,
            params: mcpParams
        } )

        // Add Mcp-Session-Id header if provided (required for Streamable HTTP after initialize)
        const headers = { ...authHeaders }
        if( sessionId ) {
            headers['Mcp-Session-Id'] = sessionId
        }

        const response = await this.makeRequest( {
            baseUrl,
            routePath,
            method: 'POST',
            headers,
            body: mcpRequest,
            timeout
        } )

        const enhancedResponse = {
            ...response,
            mcpRequest,
            mcpMethod,
            sessionId,
            isMcpResponse: response.body && typeof response.body === 'object' && 'jsonrpc' in response.body
        }

        return enhancedResponse
    }


    static async sendMcpRequestWithSession( { baseUrl, routePath, mcpMethod, mcpParams = {}, authHeaders = {}, timeout = 30000 } ) {
        // 1. Initialize MCP connection
        const initRequest = this.createMcpRequest( {
            method: 'initialize',
            params: {
                protocolVersion: '2024-11-05',
                capabilities: {},
                clientInfo: { name: 'test-client', version: '1.0.0' }
            },
            id: 1
        } )

        const initResponse = await this.makeRequest( {
            baseUrl,
            routePath,
            method: 'POST',
            headers: {
                ...authHeaders,
                'Accept': 'application/json, text/event-stream'
            },
            body: initRequest,
            timeout
        } )

        if( !initResponse.success ) {
            return {
                ...initResponse,
                error: 'Failed to initialize MCP connection',
                initRequest,
                initResponse
            }
        }

        // 2. Send actual request
        const actualRequest = this.createMcpRequest( {
            method: mcpMethod,
            params: mcpParams,
            id: 2
        } )

        const response = await this.makeRequest( {
            baseUrl,
            routePath,
            method: 'POST',
            headers: {
                ...authHeaders,
                'Accept': 'application/json, text/event-stream'
            },
            body: actualRequest,
            timeout
        } )

        return {
            ...response,
            mcpRequest: actualRequest,
            mcpMethod,
            initRequest,
            initResponse,
            isMcpResponse: response.body && typeof response.body === 'object' && 'jsonrpc' in response.body
        }
    }


    static analyzeMcpResponse( { response } ) {
        const analysis = {
            isValidMcp: false,
            hasResult: false,
            hasError: false,
            mcpVersion: null,
            requestId: null,
            resultData: null,
            errorData: null,
            diagnostics: [],
            debugInfo: {
                responseStructure: null,
                bodyType: null,
                hasJsonRpc: false,
                streamableDetected: false
            }
        }

        // 🔍 COMPREHENSIVE DEBUGGING - Log full response structure
        console.log( '\n🔬 === MCP RESPONSE DEBUG ANALYSIS ===' )
        console.log( `📊 HTTP Status: ${response.status} ${response.statusText}` )
        console.log( `📦 Response Success: ${response.success}` )
        console.log( `📄 Parse Error: ${response.parseError || 'None'}` )
        console.log( `🏗️  Body Type: ${typeof response.body}` )
        console.log( `📋 Body Structure:` )
        if( response.body ) {
            console.log( JSON.stringify( response.body, null, 2 ) )
        } else {
            console.log( '   null/undefined' )
        }
        console.log( `📜 Raw Body (first 200 chars):` )
        console.log( `   "${(response.rawBody || '').substring(0, 200)}${response.rawBody?.length > 200 ? '...' : ''}"` )
        console.log( '🔬 =====================================\n' )

        // Store debug info
        analysis.debugInfo.responseStructure = response.body
        analysis.debugInfo.bodyType = typeof response.body
        analysis.debugInfo.hasJsonRpc = response.body && typeof response.body === 'object' && 'jsonrpc' in response.body

        if( !response.success ) {
            analysis.diagnostics.push( `HTTP request failed: ${response.status} ${response.statusText}` )
            return analysis
        }

        if( response.parseError ) {
            analysis.diagnostics.push( `JSON parse error: ${response.parseError}` )
            return analysis
        }

        const body = response.body
        if( !body || typeof body !== 'object' ) {
            analysis.diagnostics.push( 'Response body is not a valid JSON object' )
            return analysis
        }

        if( !body.jsonrpc ) {
            analysis.diagnostics.push( 'Missing jsonrpc field in response' )
            return analysis
        }

        analysis.isValidMcp = true
        analysis.mcpVersion = body.jsonrpc
        analysis.requestId = body.id

        if( body.result !== undefined ) {
            analysis.hasResult = true
            analysis.resultData = body.result
        }

        if( body.error !== undefined ) {
            analysis.hasError = true
            analysis.errorData = body.error
            analysis.diagnostics.push( `MCP error: ${body.error.message || 'Unknown error'}` )
        }

        return analysis
    }
}


export { StreamableTransport }