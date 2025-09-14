import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { SchemaImporter } from 'schemaImporter'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

function getServerParams( { path, requiredServerParams } ) {
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

    selection
        .forEach( ( row ) => {
            const [ key, _ ] = row
            if( !result[ key ]  ) { console.log( `Missing ${key} in .env file` ) }
            return true
        } )

    return result
}

const envParams = getServerParams( {
    'path': path.resolve(__dirname, '../../../.auth.env'),
    'requiredServerParams': [
        'FIRST_ROUTE_AUTH0_DOMAIN',
        'FIRST_ROUTE_AUTH0_CLIENT_ID',
        'FIRST_ROUTE_AUTH0_CLIENT_SECRET',
        'THIRD_ROUTE_BEARER_TOKEN',
        'SCALEKIT_ENVIRONMENT_URL',
        'SCALEKIT_CLIENT_ID',
        'SCALEKIT_CLIENT_SECRET',
        'SCALEKIT_MCP_ID'
    ]
} )

const {
    FIRST_ROUTE_AUTH0_DOMAIN: firstRouteAuth0Domain,
    FIRST_ROUTE_AUTH0_CLIENT_ID: firstRouteAuth0ClientId,
    FIRST_ROUTE_AUTH0_CLIENT_SECRET: firstRouteAuth0ClientSecret,
    THIRD_ROUTE_BEARER_TOKEN: thirdRouteBearerToken,
    SCALEKIT_ENVIRONMENT_URL: scalekitEnvironmentUrl,
    SCALEKIT_CLIENT_ID: scalekitClientId,
    SCALEKIT_CLIENT_SECRET: scalekitClientSecret,
    SCALEKIT_MCP_ID: scalekitMcpId
} = envParams

const config = {
    'silent': false, // Set to true to disable OAuth route output  
    'envPath': './../../.env',
    'rootUrl': 'http://localhost', // optional
    'port': 3001, // optional
    'baseUrl': 'http://localhost:3001', // Global base URL for all OAuth endpoints
    'forceHttps': false, // Global HTTPS enforcement (can be overridden per route)
    'routeConfigs': [
/*
        {
            'authType': 'oauth21_auth0',
            'routePath': '/first-route',
            'name': 'First Auth0 Route',
            'description': 'Testing first Auth0 client configuration with ERC20 schemas',
            'bearerIsPublic': false,
            'protocol': 'sse',
            'schemas': async() => {
                const all = await SchemaImporter
                    .loadFromFolder( {
                        excludeSchemasWithImports: true,
                        excludeSchemasWithRequiredServerParams: true,
                        addAdditionalMetaData: false
                    } )
                const arrayOfSchemas = all
                    .map( ( { schema } ) => schema )
                    .filter( ( _, index ) => index === 0 ) // nur das erste Schema nehmen

                return { arrayOfSchemas }
            },
            'auth': {
                'enabled': true,
                'authType': 'oauth21_auth0',
                'providerName': 'auth0', // EXPLICIT PROVIDER SPECIFICATION
                'providerUrl': `https://${firstRouteAuth0Domain}`,
                'realm': 'first-route-realm', // Auth0 pseudo-realm für erste Route
                'clientId': firstRouteAuth0ClientId || 'your-first-route-client-id',
                'clientSecret': firstRouteAuth0ClientSecret || 'your-first-route-client-secret',
                'scope': 'openid profile email',
                'audience': 'http://localhost:3000/first-route/sse',
                'authFlow': 'authorization_code',
                'requiredScopes': [ 'openid', 'profile', 'email' ],
                'requiredRoles': [ 'user' ],
                'resourceUri': null,
                'forceHttps': true
            }
        },
*/
        {
            'authType': 'oauth21_scalekit',
            'routePath': '/scalekit-route',
            'name': 'ScaleKit Route',
            'description': 'Testing ScaleKit OAuth 2.1 configuration with MCP schemas',
            'bearerIsPublic': false,
            'protocol': 'sse',
            'schemas': async() => {
                const all = await SchemaImporter
                    .loadFromFolder( {
                        excludeSchemasWithImports: true,
                        excludeSchemasWithRequiredServerParams: true,
                        addAdditionalMetaData: false
                    } )
                const arrayOfSchemas = all
                    .map( ( { schema } ) => schema )
                    .filter( ( _, index ) => index === 1 ) // zweites Schema für ScaleKit Route

                return { arrayOfSchemas }
            },
            'auth': {
                'enabled': true,
                'authType': 'oauth21_scalekit',
                'providerUrl': scalekitEnvironmentUrl,
                'mcpId': scalekitMcpId,
                'clientId': scalekitClientId,
                'clientSecret': scalekitClientSecret,
                'resource': 'http://localhost:3001/scalekit-route',  // The actual MCP server endpoint
                'resourceDocumentation': 'http://localhost:3001/scalekit-route/docs',
                'scope': 'openid profile mcp:tools mcp:resources:read mcp:resources:write',
                'authFlow': 'authorization_code',
                'forceHttps': false
            }
        },
/*
        {
            'routePath': '/third-route',
            'name': 'Third Route',
            'description': 'A third route without authentication',
            'protocol': 'sse',
            'schemas': async() => {
                const all = await SchemaImporter
                    .loadFromFolder( {
                        excludeSchemasWithImports: true,
                        excludeSchemasWithRequiredServerParams: true,
                        addAdditionalMetaData: false
                    } )
                const arrayOfSchemas = all
                    .map( ( { schema } ) => schema )
                    .filter( ( _, index ) => index === 2 ) // nur das dritte Schema nehmen

                return { arrayOfSchemas }
            },
            'auth': {
                'enabled': true,
                'authType': 'staticBearer',
                'token': thirdRouteBearerToken
            }
        },
*/
    ]
}

const { rootUrl, port } = config
config['routeConfigs'] = config['routeConfigs']
    .map( ( route ) => {
        const { auth: { authType } } = route
        const { routePath } = route
        if( authType === 'oauth21_auth0' ) {
            route['auth']['resourceUri'] = `${rootUrl}:${port}${routePath}`
        }
        // ScaleKit resource must match dashboard configuration, don't override
        // if( authType === 'oauth21_scalekit' ) {
        //     route['auth']['resource'] = `${rootUrl}:${port}${routePath}`
        // }
        return route
    } )

export { config }