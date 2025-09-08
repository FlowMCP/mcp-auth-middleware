import { SchemaImporter } from 'schemaImporter'
import { DeployAdvanced } from 'flowmcpServers'
import { OAuthMiddleware } from '../../src/index.mjs'
import { TestUtils } from '../helpers/utils.mjs'


// Load Auth0 credentials for both routes from .auth.env
const envParams = TestUtils.getEnvParams( {
    'envPath': './../../.auth.env',
    'selection': [
        [ 'firstRouteAuth0Domain',        'FIRST_ROUTE_AUTH0_DOMAIN'         ],
        [ 'firstRouteAuth0ClientId',      'FIRST_ROUTE_AUTH0_CLIENT_ID'      ],
        [ 'firstRouteAuth0ClientSecret',  'FIRST_ROUTE_AUTH0_CLIENT_SECRET'  ],
        [ 'secondRouteAuth0Domain',       'SECOND_ROUTE_AUTH0_DOMAIN'        ],
        [ 'secondRouteAuth0ClientId',     'SECOND_ROUTE_AUTH0_CLIENT_ID'     ],
        [ 'secondRouteAuth0ClientSecret', 'SECOND_ROUTE_AUTH0_CLIENT_SECRET' ]
    ]
} )
const { 
    firstRouteAuth0Domain, 
    firstRouteAuth0ClientId, 
    firstRouteAuth0ClientSecret,
    secondRouteAuth0Domain, 
    secondRouteAuth0ClientId, 
    secondRouteAuth0ClientSecret 
} = envParams


const config = {
    'silent': false, // Set to true to disable OAuth route output  
    'envPath': './../../.env',
    'rootUrl': 'http://localhost', // optional
    'port': 3002, // optional
    'routes': [
        {
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
                'providerName': 'auth0', // EXPLICIT PROVIDER SPECIFICATION
                'providerUrl': `https://${firstRouteAuth0Domain}`,
                'realm': 'first-route-realm', // Auth0 pseudo-realm für erste Route
                'clientId': firstRouteAuth0ClientId || 'your-first-route-client-id',
                'clientSecret': firstRouteAuth0ClientSecret || 'your-first-route-client-secret',
                'requiredScopes': ['openid', 'profile', 'email']
                // resourceUri: `${rootUrl}:${port}/eerc20` <--- muss später abgeleitet werden von rootUrl und port
            }
        },
        {
            'routePath': '/second-route',
            'name': 'Second Auth0 Route',
            'description': 'Testing second Auth0 client configuration with different schemas',
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
                    .filter( ( _, index ) => index === 1 ) // nur das zweite Schema nehmen

                return { arrayOfSchemas }
            },
            'auth': {
                'enabled': true,
                'providerName': 'auth0', // EXPLICIT PROVIDER SPECIFICATION
                'providerUrl': `https://${secondRouteAuth0Domain}`,
                'realm': 'second-route-realm', // Auth0 pseudo-realm für zweite Route
                'clientId': secondRouteAuth0ClientId || 'your-second-route-client-id',
                'clientSecret': secondRouteAuth0ClientSecret || 'your-second-route-client-secret',
                'requiredScopes': ['openid', 'profile', 'email']
                // resourceUri: `${rootUrl}:${port}/eerc20` <--- muss später abgeleitet werden von rootUrl und port
            }
        }
    ]
}

const { routes, rootUrl, port, silent } = config

const realmsByRoute = routes
    .reduce( ( acc, route ) => {
        const { routePath, auth, protocol } = route
        if( !auth.enabled ) { return acc }
        const { providerName, providerUrl, realm, clientId, clientSecret, requiredScopes } = auth
        const resourceUri = `${rootUrl}:${port}${routePath}`  // Base URL without protocol suffix
        acc[ routePath ] = { providerName, providerUrl, realm, clientId, clientSecret, requiredScopes, resourceUri }
        return acc
    }, {} )

const oauthMiddleware = await OAuthMiddleware
    .create( { realmsByRoute, silent } )


const modifiedRoutes = routes
    .map( ( route ) => { return { ...route, bearerToken: null } } )

const objectOfSchemaArrays = await modifiedRoutes
    .reduce( async ( promiseAcc, route ) => {
        const acc = await promiseAcc
        const { routePath, schemas } = route
        const { arrayOfSchemas } = await schemas()
        acc[ routePath ] = arrayOfSchemas
        return acc
    }, Promise.resolve( {} ) )

const arrayOfRoutes = modifiedRoutes
    .map( ( route ) => {
        const { routePath, protocol = 'sse', bearerToken } = route
        const schemasForRoute = objectOfSchemaArrays[ routePath ] || []
        if( schemasForRoute.length === 0 && !silent ) {
            console.warn( `⚠️  No schemas found for route ${routePath}` )
        }
        return { routePath, protocol, bearerToken }
    } )

const { app, mcps, events, argv, server } = DeployAdvanced
    .init( { silent } )

// Register OAuth middleware on the Express app
app.use( oauthMiddleware.router() )

DeployAdvanced
    .start( { arrayOfRoutes, objectOfSchemaArrays, envObject: [], rootUrl, port } )
