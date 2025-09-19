import express from 'express'
import { randomUUID } from 'node:crypto'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'

import { ConfigManager } from '../../.trash/ConfigManager.mjs'
import { McpAuthMiddleware } from '../../src/index.mjs'



const authTypKey = 'oauth21_scalekit'

const { config, authTypValue } = await ConfigManager.getConfig( { authTypKey } )
const { silent, baseUrl, forceHttps, routePath, fullPath, port } = config


const app = express()
app.use( express.json() )

// Create middleware with new API structure - ScaleKit OAuth21
const oauthMiddleware = await McpAuthMiddleware.create({
    oauth21: {
        authType: 'oauth21_scalekit',
        attachedRoutes: [routePath, '/scalekit-route/streamable'],
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

// Create MCP server instance
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

// Create streamable HTTP transport
const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID()
})

// Connect MCP server to transport
await server.connect( transport )

// Mount the transport handler for public streamable endpoint (unprotected)
app.use( '/public/streamable', async ( req, res ) => {
    try {
        const parsedBody = req.body || {}
        await transport.handleRequest( req, res, parsedBody )
    } catch ( error ) {
        console.error( 'Transport error:', error )
        res.status( 500 ).json( { error: 'Internal server error' } )
    }
} )

// Mount the transport handler for protected streamable endpoint
app.use( '/scalekit-route/streamable', async ( req, res ) => {
    try {
        const parsedBody = req.body || {}
        await transport.handleRequest( req, res, parsedBody )
    } catch ( error ) {
        console.error( 'Transport error:', error )
        res.status( 500 ).json( { error: 'Internal server error' } )
    }
} )

// Mount the transport handler for SSE endpoint (original)
app.use( routePath, async ( req, res ) => {
    try {
        const parsedBody = req.body || {}
        await transport.handleRequest( req, res, parsedBody )
    } catch ( error ) {
        console.error( 'Transport error:', error )
        res.status( 500 ).json( { error: 'Internal server error' } )
    }
} )

app.listen( 3000, () => console.log( `MCP server running on ${fullPath}` ) )