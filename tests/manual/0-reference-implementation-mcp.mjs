import express from 'express'
import { randomUUID } from 'node:crypto'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js'

import { ConfigManager } from './ConfigManager.mjs'
import { McpAuthMiddleware } from '../../src/index.mjs'



const authTypKey = 'oauth21_scalekit'

const { config, authTypValue } = await ConfigManager.getConfig( { authTypKey } )
const { silent, baseUrl, forceHttps, routePath, fullPath, port } = config


const server = new McpServer( { 'name': 'my-app', 'version': '1.0.0' } )
const app = express()
app.use( express.json() )

// Create middleware with new API structure - ScaleKit OAuth21
const oauthMiddleware = await McpAuthMiddleware.create({
    oauth21: {
        authType: 'oauth21_scalekit',
        attachedRoutes: [routePath],
        options: {
            providerUrl: authTypValue.providerUrl,
            mcpId: authTypValue.mcpId,
            clientId: authTypValue.clientId,
            clientSecret: authTypValue.clientSecret,
            resource: authTypValue.resource,
            scope: authTypValue.scope
        }
    },
    silent: false,
    baseUrl: `${baseUrl}:${port}`,
    forceHttps
})

app.use( oauthMiddleware.router() )

const transports = {}
app.post( routePath, async ( req, res ) => {
    const sessionId = req.headers['mcp-session-id']
    let transport = sessionId && transports[sessionId]

    if (!transport && isInitializeRequest(req.body)) {
        transport = new StreamableHTTPServerTransport( {
            sessionIdGenerator: randomUUID,
            onsessioninitialized: id => ( transports[ id ] = transport ),
        } )
        transport.onclose = () => delete transports[ transport.sessionId ]

        const server = new McpServer( { name: 'example-server', version: '1.0.0' } )

        // Register multiple tools for testing
        server.registerTool(
            'ping',
            {
                'title': 'Ping',
                'description': 'Simple ping tool that responds with pong'
            },
            async () => ( {
                content: [ { type: 'text', text: 'pong' } ]
            } )
        )

        server.registerTool(
            'echo',
            {
                'title': 'Echo',
                'description': 'Echo back the provided message'
            },
            async ( { message = 'hello' } ) => ( {
                content: [ { type: 'text', text: `Echo: ${message}` } ]
            } )
        )

        server.registerTool(
            'add',
            {
                'title': 'Add',
                'description': 'Add two numbers'
            },
            async ( { a = 2, b = 3 } ) => ( {
                content: [ { type: 'text', text: `Result: ${a + b}` } ]
            } )
        )

        await server.connect( transport )
    }

    if (!transport) {
        return res
            .status( 400 )
            .json( { jsonrpc: '2.0', error: { code: -32000, message: 'Bad Request' }, id: null } )
    }

    await transport.handleRequest( req, res, req.body )
} )

const handleSession = async ( req, res ) => {
    const t = transports[ req.headers['mcp-session-id'] ]
    if( !t ) { return res.status( 400 ).send( 'Invalid session' ) }
    await t.handleRequest( req, res )
}

app.get( routePath, handleSession )
app.delete( routePath, handleSession )

app.listen( 3000, () => console.log( `MCP server running on ${fullPath}` ) )
