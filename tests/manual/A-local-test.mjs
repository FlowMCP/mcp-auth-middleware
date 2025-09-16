import { LocalTesting } from './LocalTesting.mjs'


const config = {
    'authTypes': [
        'oauth21_scalekit',
        'oauth21_auth0',
        'staticBearer'
    ],
    'serverPaths': [
        'tests/manual/0-reference-implementation-mcp.mjs',
        'tests/manual/1-reference-implementation-flowmcp.mjs'
    ]
}

const { authTypes, serverPaths } = config
const  { authType: authTypKey, serverPath } = LocalTesting.parseArgv( { argv: process.argv } )
const { status, messages } = LocalTesting.validationArgv( { authTypKey, serverPath, authTypes, serverPaths } )
if( !status ) { throw new Error( `Input validation failed:\n- ${messages.join( '\n- ' )}` ) }

await LocalTesting.start( { authTypKey, serverPath } )