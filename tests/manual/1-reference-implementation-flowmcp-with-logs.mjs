import cors from 'cors'
import { DeployAdvanced } from 'flowmcpServers'
import { McpAuthMiddleware } from '../../src/index.mjs'
import { config } from './config.mjs'


const { routeConfigs, silent, baseUrl, forceHttps } = config

console.log( '🔧 Starting FlowMCP OAuth Middleware Setup...' )
console.log( '📋 Configuration:' )
console.log( `   Base URL: ${baseUrl}` )
console.log( `   Force HTTPS: ${forceHttps}` )
console.log( `   Silent mode: ${silent}` )
console.log( `   Route configs count: ${routeConfigs.length}` )
console.log( '' )

const objectOfMcpAuthRoutes = routeConfigs
    .reduce( ( acc, { routePath, auth, authType } ) => {
        if( !auth.enabled ) {
            console.log( `⏸️  Skipping disabled route: ${routePath}` )
            return acc
        }
        delete auth.enabled
        acc[ routePath ] = { authType, ...auth }
        console.log( `✅ Adding auth route: ${routePath} (${authType})` )
        return acc
    }, {} )

console.log( '' )
console.log( '🔐 Creating OAuth Middleware...' )
const oauthMiddleware = await McpAuthMiddleware
    .create({
        routes: objectOfMcpAuthRoutes,
        silent,
        baseUrl,
        forceHttps
    })
console.log( '✅ OAuth Middleware created successfully' )
console.log( '' )

console.log( '📊 Loading schemas...' )
const objectOfSchemaArrays = await routeConfigs
    .reduce( async ( promiseAcc, { routePath, schemas } ) => {
        const acc = await promiseAcc
        const { arrayOfSchemas } = await schemas()
        acc[ routePath ] = arrayOfSchemas
        console.log( `   📁 Loaded ${arrayOfSchemas.length} schemas for ${routePath}` )
        return acc
    }, Promise.resolve( {} ) )

console.log( '✅ All schemas loaded' )
console.log( '' )

const arrayOfRoutes = routeConfigs
    .map( ( { routePath, protocol, bearerIsPublic } ) => {
        const route = {
            routePath,
            protocol,
            bearerToken: bearerIsPublic === false ? 'required' : null
        }
        console.log( `🛣️  Route: ${routePath} - Protocol: ${protocol} - Bearer: ${route.bearerToken || 'optional'}` )
        return route
    } )

console.log( '' )
console.log( '🚀 Initializing DeployAdvanced...' )
const { app, mcps, events, argv, server } = DeployAdvanced
    .init( { silent } )

// Enable trust proxy for correct protocol detection behind reverse proxies
app.set( 'trust proxy', true )
console.log( '🔧 Trust proxy enabled' )

// CORS für Inspector-Zugriff
app.use( cors( {
    origin: '*',
    methods: [ 'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS' ],
    allowedHeaders: [ 'Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'mcp-protocol-version' ]
} ) )
console.log( '🌐 CORS middleware configured' )

// Request logging middleware
app.use( ( req, res, next ) => {
    const timestamp = new Date().toISOString()
    const method = req.method
    const url = req.url
    const userAgent = req.get('User-Agent') || 'Unknown'
    const ip = req.ip || req.connection.remoteAddress || 'Unknown'

    console.log( `📥 ${timestamp} - ${method} ${url}` )
    console.log( `   IP: ${ip}` )
    console.log( `   User-Agent: ${userAgent}` )

    if( req.headers.authorization ) {
        console.log( `   🔐 Authorization: Bearer ${req.headers.authorization.substring(0, 20)}...` )
    }

    if( Object.keys( req.query ).length > 0 ) {
        console.log( `   Query: ${JSON.stringify( req.query )}` )
    }

    console.log( '' )
    next()
} )
console.log( '📊 Request logging middleware configured' )

app.use( oauthMiddleware.router() )
console.log( '🔐 OAuth middleware router registered' )

const { rootUrl, port } = config
console.log( '' )
console.log( `🎯 Starting server on ${rootUrl}:${port}...` )
DeployAdvanced
    .start( { arrayOfRoutes, objectOfSchemaArrays, envObject: [], rootUrl, port } )

console.log( '✨ FlowMCP OAuth Middleware is ready!' )