import express from 'express'
import { randomUUID } from 'node:crypto'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { OAuthMiddlewareTester } from './../../src/index.mjs'


import fs from 'fs'
import { fileURLToPath } from 'url'
import path from 'path'

const __filename = fileURLToPath( import.meta.url ) 
const __dirname = path.dirname( __filename )


class ConfigExamples {
    #state = {}

    constructor( { envPath, routePath, silent=false } ) {
        this.#state = this.#setState( { envPath, routePath, silent } )
    }


    getState() {
        return this.#state
    }


    parseUserInput( { argv } ) {
        const args = argv.slice( 2 ) 
        const parsed =  argv
            .reduce( ( acc, arg ) => {
                if( arg.startsWith( '--' ) && arg.includes( '=' ) ) {
                    const [ key, value ] = arg.split( '=' )
                    const cleanKey = key.substring( 2 )
                    acc[ cleanKey ] = value
                }

                return acc
            }, {} )

        if( !Object.keys( parsed ).includes( 'routeType' ) ) {
            throw new Error( 'Missing --routeType argument. Valid values: free-route, static-bearer, oauth' )
        }

        return parsed
    }


    getMcpAuthConfig( { routeType } ) {
        let mcpAuthConfig = null
        switch( routeType ) {
            case 'free-route':
                mcpAuthConfig = this.getMcpAuthFreeConfig()['mcpAuthConfig']
                break
            case 'static-bearer':
                mcpAuthConfig = this.getMcpAuthBearerConfig()['mcpAuthConfig']
                break
            case 'oauth':
                mcpAuthConfig = this.getMcpAuthScaleKitConfig()['mcpAuthConfig']
                break
            default:
                throw new Error(`Invalid routeType: ${routeType}. Valid values: free-route, static-bearer, oauth`)
        }

        return { mcpAuthConfig }
    }



    getMcpAuthBearerConfig() {
        const { routePath, silent, forceHttps, baseUrl, bearerSecretToken } = this.#state

        const staticBearer = {
            tokenSecret: bearerSecretToken,
            attachedRoutes: [ routePath ]
        }

        const mcpAuthConfig = { staticBearer,  oauth21: null, silent, baseUrl, bearerSecretToken, forceHttps }

        return { mcpAuthConfig }
    }


    getMcpAuthFreeConfig() {
        const { silent, forceHttps, baseUrl } = this.#state

        // Free route - no authentication required
        const mcpAuthConfig = {
            staticBearer: null,
            oauth21: null,
            silent,
            baseUrl,
            forceHttps
        }

        return { mcpAuthConfig }
    }


    getMcpAuthScaleKitConfig() {
        const { routePath, silent, forceHttps, baseUrl } = this.#state
        const envParams = this.#getScaleKitEnvParams()

        const oauth21 = {
            authType: 'oauth21_scalekit',
            attachedRoutes: [ routePath ],
            options: {
                providerUrl: envParams.SCALEKIT_ENVIRONMENT_URL,
                mcpId: envParams.SCALEKIT_MCP_ID,
                clientId: envParams.SCALEKIT_CLIENT_ID,
                clientSecret: envParams.SCALEKIT_CLIENT_SECRET,
                resource: envParams.SCALEKIT_ORGANIZATION_ID,
                scope: 'openid profile email'
            }
        }

        const mcpAuthConfig = {
            staticBearer: null,
            oauth21,
            silent,
            baseUrl,
            forceHttps
        }

        // OAuth21Config for testing needs organizationId field directly
        const oauth21Config = {
            ...oauth21.options,
            organizationId: envParams.SCALEKIT_ORGANIZATION_ID
        }

        return { mcpAuthConfig, oauth21Config }
    }


    #getScaleKitEnvParams() {
        const envObject = this.#getServerParams( {
            path: path.resolve( __dirname, this.#state.envPath ),
            requiredServerParams: [
                'SCALEKIT_ENVIRONMENT_URL',
                'SCALEKIT_CLIENT_ID',
                'SCALEKIT_CLIENT_SECRET',
                'SCALEKIT_MCP_ID',
                'SCALEKIT_ORGANIZATION_ID'
            ]
        } )

        return envObject
    }


    getDemoMcpTool() {
        const name = 'ping'
        const instrcution = {
            'title': 'Ping',
            'description': 'Simple ping tool that responds with pong'
        }
        const _func = async () => ( {
            content: [ { type: 'text', text: 'pong' } ]
        } )

        return { name, instrcution, _func }
    }


    async runServer( { oauthMiddleware, serverPort, registerTools } ) {
        const { routePath, fullPath } = this.#state

        const app = express()
        app.use( express.json() )
        app.use( oauthMiddleware.router() )

        const server = new McpServer( { name: 'example-server', version: '1.0.0' } )

        registerTools
            .forEach( ( { name, instrcution, _func } ) => {
                server.registerTool( name, instrcution, _func )
            } )

        const transport = new StreamableHTTPServerTransport( {
            sessionIdGenerator: () => randomUUID() 
        } )
        await server.connect( transport )
        app.use( routePath, async ( req, res ) => {
            try {
                const parsedBody = req.body || {}
                await transport.handleRequest( req, res, parsedBody )
            } catch ( error ) {
                console.error( 'Transport error:', error )
                res.status( 500 ).json( { error: 'Internal server error' } )
            }
        } )

        app.listen( serverPort, () => console.log( `MCP server running on ${fullPath}` ) )
    }


    async startTest( { routeType } ) {
        const { baseUrl, routePath, bearerSecretToken: bearerToken } = this.#state

        if( routeType === 'free-route' ) {
            console.log( '🚀 Starting OAuthMiddlewareTester for free-route...' )
            await OAuthMiddlewareTester.testStreamableRoute( {
                baseUrl,
                routePath,
                timeout: 30000,
                expectedStatus: 200
            } )
        } else if( routeType === 'static-bearer' ) {
            console.log( '🚀 Starting OAuthMiddlewareTester for static-bearer...' )
            await OAuthMiddlewareTester.testBearerStreamable( {
                baseUrl,
                routePath,
                bearerToken,
                timeout: 30000,
                testUnauthorized: true,
                expectedUnauthorizedStatus: 401
            } )
        } else if( routeType === 'oauth' ) {
            console.log( '🚀 Starting OAuthMiddlewareTester for oauth (ScaleKit)...' )
            const { oauth21Config } = this.getMcpAuthScaleKitConfig()
            await OAuthMiddlewareTester.testOAuthStreamable( {
                baseUrl,
                routePath,
                oauth21Config,
                browserTimeout: 90000,
                silent: false,
                testUnauthorized: true,
                expectedUnauthorizedStatus: 401
            } )
        } else {
            throw new Error( `routeType ${routeType} not implemented yet` )
        }

        return true
    }



    #setState( { envPath, routePath, silent } ) {
        const envObject = this.#getServerParams( { 
            path: path.resolve( __dirname, envPath ),
            requiredServerParams: [
                'SERVER_URL',
                'SERVER_PORT',
                'BEARER_TOKEN_MASTER',
                'SCALEKIT_ENVIRONMENT_URL',
                'SCALEKIT_CLIENT_ID',
                'SCALEKIT_CLIENT_SECRET',
                'SCALEKIT_MCP_ID',
                'SCALEKIT_ORGANIZATION_ID'
            ]
        } )
        let baseUrl = null
        const { SERVER_URL, SERVER_PORT, BEARER_TOKEN_MASTER } = envObject
        if( SERVER_PORT === '80' || SERVER_PORT === '443' ) {
            baseUrl = SERVER_URL
        } else {
            baseUrl = `${SERVER_URL}:${SERVER_PORT}`
        }

        const state = {}
        state['envPath'] = envPath
        state['routePath'] = routePath
        state['silent'] = silent
        state['baseUrl'] = baseUrl
        state['forceHttps'] = false
        state['bearerSecretToken'] = BEARER_TOKEN_MASTER
        state['fullPath'] = `${state.baseUrl}${routePath}`
        state['serverPort'] = parseInt( SERVER_PORT, 10 )

        return state
    }


    #getServerParams( { path, requiredServerParams } ) {
        const selection = requiredServerParams
            .map( ( serverParam ) => [ serverParam, serverParam ] )

        const result = fs
            .readFileSync( path, 'utf-8' )
            .split( "\n" )
            .map( line => line.split( '=' ) )
            .reduce( ( acc, [ k, v ] ) => {
                const find = selection.find( ( [ _, value ] ) => value === k )
                if( find ) {  acc[ find[ 0 ] ] = v  }
                return acc
            }, {} )

        const messages = []
        selection
            .forEach( ( row ) => {
                const [ key, _ ] = row
                if( !result[ key ]  ) { messages.push( `Missing ${key} in .env file` ) }
                return true
            } )
        if( messages.length > 0 ) {
            throw new Error( messages.join( "\n" ) )
        }

        return result
    }
}


export { ConfigExamples }