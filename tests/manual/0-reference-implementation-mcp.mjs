import express from 'express'
import cors from 'cors'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'

import { McpAuthMiddleware } from '../../src/index.mjs'
import { config } from './config.mjs'


const app = express()
app.use( express.json() )

// CORS für Inspector-Zugriff
app.use( cors( {
    origin: ['http://localhost:6274', 'http://localhost:3000'],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false
} ) )

const { routeConfigs, silent, port, rootUrl } = config
routeConfigs
    .forEach( ( a ) => {
        console.log( a )
        const { routePath } = a
        app.post( routePath, async ( req, res ) => {
            const server = new McpServer()
            server.registerTool( 
                'add',
                {
                    title: 'Addition Tool',
                    description: 'Add two numbers',
                    inputSchema: { a: z.number(), b: z.number() }
                },
                async ( { a, b } ) => ( {
                    content: [ { type: 'text', text: String( a + b ) } ]
                } )
            )

            const transport = new StdioServerTransport()
            await server.connect( transport )
            await transport.handleRequest( req, res, req.body )
        } )
    } )

const objectOfMcpAuthRoutes = routeConfigs
    .reduce( ( acc, { routePath, auth, authType } ) => {
        if( !auth.enabled ) { return acc }
        delete auth.enabled
        acc[ routePath ] = { authType, ...auth }
        return acc
    }, {} )

const oauthMiddleware = await McpAuthMiddleware
    .create( { routes: objectOfMcpAuthRoutes, silent } )

app.use( oauthMiddleware.router() )

app.listen( port )





