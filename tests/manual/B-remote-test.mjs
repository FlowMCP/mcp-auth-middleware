import { RemoteTesting } from './RemoteTesting.mjs'


const config = {
    'remoteUrls': [
        'http://community.flowmcp.org/scalekit-route/sse/',
        'https://api.flowmcp.org/auth-route/streamable/',
        'http://localhost:3000/test-route/streamable/'
    ]
}

const { remoteUrls } = config
const { remoteUrl } = RemoteTesting.parseArgv( { argv: process.argv } )
const { status, messages } = RemoteTesting.validationArgv( { remoteUrl, remoteUrls } )
if( !status ) { throw new Error( `Input validation failed:\n- ${messages.join( '\n- ' )}` ) }

await RemoteTesting.start( { remoteUrl } )