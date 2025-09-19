import { McpAuthMiddleware } from '../../src/index.mjs'
import { ConfigExamples } from './ConfigExamples.mjs'

const config = {
    'envPath': '../../../.auth.env',
    'routePath': '/ping'
}

const { envPath, routePath } = config
const configExamples = new ConfigExamples( { envPath, routePath } )
const { serverPort } = configExamples.getState()
const { routeType } = configExamples.parseUserInput( { argv: process.argv } )
const { mcpAuthConfig } = configExamples.getMcpAuthConfig( { routeType } )
const oauthMiddleware = await McpAuthMiddleware
    .create( mcpAuthConfig )
const { name, instrcution, _func } = configExamples.getDemoMcpTool()
const registerTools = []
registerTools.push( { name, instrcution, _func } )
await configExamples.runServer( { oauthMiddleware, serverPort, registerTools } )
const delay = ms => new Promise( res => setTimeout( res, ms ) )
await delay( 1000 )
await configExamples.startTest( { routeType } )
process.exit( 0 )



