import { McpAuthMiddleware } from '../../src/index.mjs'
import { ConfigExamples } from './helpers/ConfigExamples.mjs'

const config = {
    'envPath': '../../../../.auth.env',
    'routePath': '/'
}

const { envPath, routePath } = config
const configExamples = new ConfigExamples( { envPath, routePath } )
const { serverPort, app } = configExamples
    .getState()
const { routeType, mcpType } = configExamples
    .parseUserInput( { argv: process.argv } )
const { mcpAuthConfig } = configExamples
    .getMcpAuthConfig( { routeType } )

// M-C-P--A-U-T-H------------------------------
const oauthMiddleware = await McpAuthMiddleware
    .create( mcpAuthConfig )
app.use( oauthMiddleware.router() )
// --------------------------------------------

const { tools } = await configExamples
    .getTools( { mcpType } )
await configExamples
    .runServer( { serverPort, mcpType, tools } )
