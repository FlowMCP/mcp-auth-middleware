import { RemoteTesting } from './RemoteTesting.mjs'


const config = {
    'remoteUrls': [
        'http://localhost:3000/scalekit-route/sse',
        'http://localhost:8080/scalekit-route/sse',
        'http://community.flowmcp.org/scalekit-route/sse/',
    ]
}

const { remoteUrls } = config
// const { remoteUrl } = RemoteTesting.parseArgv( { argv: process.argv } )
const remoteUrl = remoteUrls[0]  // For now, just use the first URL for testing
const { status, messages } = RemoteTesting.validationArgv( { remoteUrl, remoteUrls } )
if( !status ) { throw new Error( `Input validation failed:\n- ${messages.join( '\n- ' )}` ) }

await RemoteTesting.start( { remoteUrl } )