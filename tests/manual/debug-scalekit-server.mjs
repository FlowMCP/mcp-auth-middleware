import express from 'express'

import { McpAuthMiddleware } from '../../src/index.mjs'
import { config } from './config.mjs'


const app = express()

// Enable trust proxy for correct protocol detection behind reverse proxies
app.set( 'trust proxy', true )

app.use( express.json() )

// Simple CORS implementation without external dependency
app.use( ( req, res, next ) => {
    const allowedOrigins = ['http://localhost:6274', 'http://localhost:3000', 'http://localhost:6277']
    const origin = req.headers.origin
    if( allowedOrigins.includes( origin ) ) {
        res.setHeader( 'Access-Control-Allow-Origin', origin )
    }
    res.setHeader( 'Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE' )
    res.setHeader( 'Access-Control-Allow-Headers', 'Content-Type, Authorization, mcp-protocol-version, Accept, Origin, X-Requested-With' )
    res.setHeader( 'Access-Control-Allow-Credentials', 'false' )
    if( req.method === 'OPTIONS' ) {
        res.sendStatus( 200 )
    } else {
        next()
    }
} )

// Add a test route to verify server is working
app.get( '/', ( req, res ) => {
    res.json( { status: 'Server is running', routes: ['/scalekit-route'] } )
} )

// Override config baseUrl to match debug port BEFORE using it
config.baseUrl = 'http://localhost:3001'

const { routeConfigs, silent, rootUrl } = config
const port = 3001 // Use different port for debugging

// Create OAuth middleware
const objectOfMcpAuthRoutes = routeConfigs
    .reduce( ( acc, { routePath, auth, authType } ) => {
        if( !auth.enabled ) { return acc }
        delete auth.enabled
        acc[ routePath ] = { authType, ...auth }
        return acc
    }, {} )

console.log( 'Creating OAuth middleware with routes:', Object.keys( objectOfMcpAuthRoutes ) )

const oauthMiddleware = await McpAuthMiddleware
    .create( { routes: objectOfMcpAuthRoutes, silent, baseUrl: config.baseUrl } )

app.use( oauthMiddleware.router() )

console.log( `Server starting on port ${port}` )
console.log( `Available routes:` )
console.log( `- GET  http://localhost:${port}/` )
console.log( `- GET  http://localhost:${port}/scalekit-route` )

app.listen( port, () => {
    console.log( `🚀 Debug server running at http://localhost:${port}` )
} )