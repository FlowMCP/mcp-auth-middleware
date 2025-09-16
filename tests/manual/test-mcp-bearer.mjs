import fetch from 'node-fetch'

const baseUrl = 'http://localhost:3000'
const routePath = '/scalekit-route/streamable'
const bearerToken = 'supersecure'

async function testMcpWithBearer() {
    console.log('🧪 Testing MCP with Bearer Token')
    console.log('================================')

    try {
        // Step 1: Initialize MCP session
        console.log('\n📤 Sending MCP Initialize request...')
        const initRequest = {
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
                protocolVersion: '2024-11-05',
                capabilities: {},
                clientInfo: {
                    name: 'test-client',
                    version: '1.0.0'
                }
            }
        }

        const initResponse = await fetch(`${baseUrl}${routePath}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${bearerToken}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/event-stream'
            },
            body: JSON.stringify(initRequest)
        })

        if (!initResponse.ok) {
            const errorText = await initResponse.text()
            throw new Error(`Initialize failed: ${initResponse.status} - ${errorText}`)
        }

        const sessionId = initResponse.headers.get('mcp-session-id')
        console.log(`✅ Session initialized: ${sessionId}`)

        // Parse response - it might be SSE format
        const responseText = await initResponse.text()
        console.log('📥 Initialize response:', responseText)

        // Step 2: List tools
        console.log('\n📤 Sending tools/list request...')
        const toolsRequest = {
            jsonrpc: '2.0',
            id: 2,
            method: 'tools/list',
            params: {}
        }

        const toolsResponse = await fetch(`${baseUrl}${routePath}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${bearerToken}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json, text/event-stream',
                'mcp-session-id': sessionId
            },
            body: JSON.stringify(toolsRequest)
        })

        if (!toolsResponse.ok) {
            const errorText = await toolsResponse.text()
            throw new Error(`Tools list failed: ${toolsResponse.status} - ${errorText}`)
        }

        const toolsResponseText = await toolsResponse.text()
        console.log('📥 Tools response:', toolsResponseText)

        // Try to parse as JSON if it's not SSE
        let tools = []
        try {
            // If it's SSE format, extract the JSON from data: line
            if (toolsResponseText.includes('data:')) {
                const dataMatch = toolsResponseText.match(/data:\s*(.+)/)
                if (dataMatch) {
                    const jsonData = JSON.parse(dataMatch[1])
                    tools = jsonData.result?.tools || []
                }
            } else {
                // Regular JSON
                const jsonData = JSON.parse(toolsResponseText)
                tools = jsonData.result?.tools || []
            }
        } catch (e) {
            console.log('⚠️  Could not parse tools response as JSON')
        }

        console.log(`✅ Found ${tools.length} tools:`)
        tools.forEach(tool => {
            console.log(`   - ${tool.name}: ${tool.description}`)
        })

        // Step 3: Call first tool
        if (tools.length > 0) {
            const firstTool = tools[0]
            console.log(`\n📤 Calling tool: ${firstTool.name}`)

            const toolCallRequest = {
                jsonrpc: '2.0',
                id: 3,
                method: 'tools/call',
                params: {
                    name: firstTool.name,
                    arguments: firstTool.name === 'echo' ? { message: 'Hello MCP!' } :
                               firstTool.name === 'add' ? { a: 5, b: 3 } : {}
                }
            }

            const toolCallResponse = await fetch(`${baseUrl}${routePath}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${bearerToken}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json, text/event-stream',
                    'mcp-session-id': sessionId
                },
                body: JSON.stringify(toolCallRequest)
            })

            if (!toolCallResponse.ok) {
                const errorText = await toolCallResponse.text()
                throw new Error(`Tool call failed: ${toolCallResponse.status} - ${errorText}`)
            }

            const toolCallResponseText = await toolCallResponse.text()
            console.log('📥 Tool call response:', toolCallResponseText)
        }

        console.log('\n✅ MCP Bearer Token Test SUCCESSFUL!')

    } catch (error) {
        console.error('\n❌ Test FAILED:', error.message)
        process.exit(1)
    }
}

testMcpWithBearer()