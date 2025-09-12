import cors from 'cors'
import { DeployAdvanced } from 'flowmcpServers'
import { McpAuthMiddleware } from '../../src/index.mjs'
import { config } from './config.mjs'


const { routeConfigs, silent, baseUrl, forceHttps } = config

const objectOfMcpAuthRoutes = routeConfigs
    .reduce( ( acc, { routePath, auth, authType } ) => {
        if( !auth.enabled ) { return acc }
        delete auth.enabled
        acc[ routePath ] = { authType, ...auth }
        return acc
    }, {} )

const oauthMiddleware = await McpAuthMiddleware
    .create({ 
        routes: objectOfMcpAuthRoutes, 
        silent,
        baseUrl,
        forceHttps
    })

const objectOfSchemaArrays = await routeConfigs
    .reduce( async ( promiseAcc, { routePath, schemas } ) => {
        const acc = await promiseAcc
        const { arrayOfSchemas } = await schemas()
        acc[ routePath ] = arrayOfSchemas
        return acc
    }, Promise.resolve( {} ) )

const arrayOfRoutes = routeConfigs
    .map( ( { routePath, protocol, bearerIsPublic } ) => { 
        return { 
            routePath, 
            protocol, 
            bearerToken: bearerIsPublic === false ? 'required' : null 
        } 
    } )

const { app, mcps, events, argv, server } = DeployAdvanced
    .init( { silent } )

// Enable trust proxy for correct protocol detection behind reverse proxies
app.set( 'trust proxy', true )

// CORS für Inspector-Zugriff
app.use( cors( {
    origin: '*',
    methods: [ 'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS' ],
    allowedHeaders: [ 'Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'mcp-protocol-version' ]
} ) )

app.use( oauthMiddleware.router() )

const { rootUrl, port } = config
DeployAdvanced
    .start( { arrayOfRoutes, objectOfSchemaArrays, envObject: [], rootUrl, port } )
