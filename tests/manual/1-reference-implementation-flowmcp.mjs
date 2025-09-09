import { DeployAdvanced } from 'flowmcpServers'
import { McpAuthMiddleware } from '../../src/index.mjs'
import { config } from './config.mjs'


const { routeConfigs } = config

const objectOfMcpAuthRoutes = routeConfigs
    .reduce( ( acc, { routePath, auth } ) => {
        if( !auth.enabled ) { return acc }
        delete auth.enabled
        acc[ routePath ] = { ...auth }
        return acc
    }, {} )

const oauthMiddleware = await McpAuthMiddleware
    .create( { routes: objectOfMcpAuthRoutes, silent } )

const objectOfSchemaArrays = await routeConfigs
    .reduce( async ( promiseAcc, { routePath, schemas } ) => {
        const acc = await promiseAcc
        const { arrayOfSchemas } = await schemas()
        acc[ routePath ] = arrayOfSchemas
        return acc
    }, Promise.resolve( {} ) )

const arrayOfRoutes = routeConfigs
    .map( ( { routePath, protocol } ) => { return { routePath, protocol } } )

const { app, mcps, events, argv, server } = DeployAdvanced
    .init( { silent } )

app.use( oauthMiddleware.router() )

const { rootUrl, port } = config
DeployAdvanced
    .start( { arrayOfRoutes, objectOfSchemaArrays, envObject: [], rootUrl, port } )
