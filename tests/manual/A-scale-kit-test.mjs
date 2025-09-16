import { Testing } from './Testing.mjs'


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
const  { authType: authTypKey, serverPath } = Testing.parseArgv( { argv: process.argv } )
const { status, messages } = Testing.validationArgv( { authTypKey, serverPath, authTypes, serverPaths } )
if( !status ) { throw new Error( `Input validation failed:\n- ${messages.join( '\n- ' )}` ) }

await Testing.start( { authTypKey, serverPath } )